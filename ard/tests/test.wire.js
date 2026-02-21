/*
 * Unit tests for ARD wire format message byte patterns
 *
 * Uses a MockSock to capture pushed bytes, then verifies exact byte
 * sequences match the protocol spec. Message builder logic is replicated
 * from ard-patch.js to avoid importing browser-only dependencies.
 *
 * Run: node --test ard/tests/test.wire.js
 */

import { describe, it } from 'node:test';
import { deepStrictEqual, strictEqual } from 'node:assert';

import { AES128ECB } from '../crypto/aes128.js';

// Helper: hex string → Uint8Array
function hex(s) {
    const bytes = s.replace(/\s+/g, '').match(/.{2}/g);
    return new Uint8Array(bytes.map(b => parseInt(b, 16)));
}

// ===================================================================
//  MockSock — mirrors the push API from noVNC's Websock
// ===================================================================
class MockSock {
    constructor() { this.data = []; }
    sQpush8(v)  { this.data.push(v & 0xFF); }
    sQpush16(v) { this.data.push((v >> 8) & 0xFF, v & 0xFF); }
    sQpush32(v) { this.data.push((v >> 24) & 0xFF, (v >> 16) & 0xFF,
                                  (v >> 8) & 0xFF, v & 0xFF); }
    sQpushBytes(b) { for (const x of b) this.data.push(x); }
    flush() {}
    toBytes() { return new Uint8Array(this.data); }
}

// ===================================================================
//  Message builders (replicated from ard-patch.js)
// ===================================================================

const MSG_ENCRYPTED_EVENT = 0x10;
const MSG_SET_ENCRYPTION  = 0x12;

function sendEncryptedEvent(sock, flags, encrypted) {
    sock.sQpush8(MSG_ENCRYPTED_EVENT);
    sock.sQpush8(flags);
    sock.sQpushBytes(encrypted);
    sock.flush();
}

function sendSetEncryption(sock, cmd) {
    sock.sQpush8(MSG_SET_ENCRYPTION);
    sock.sQpush8(0);       // padding
    sock.sQpush16(cmd);    // command: 1=request, 2=acknowledge
    sock.sQpush16(1);      // level: 1=all data
    if (cmd === 1) {
        sock.sQpush16(1);  // 1 method
        sock.sQpush32(1);  // method: AES-128
    } else {
        sock.sQpush16(0);  // 0 methods for ack
    }
    sock.flush();
}

function sendRSATunnelKeyRequest(sock) {
    // [u32be payloadLen=10][u16le version=1]["RSA1"][u16be sub=0][u16be pad=0]
    sock.sQpush32(10);       // payload length (u32be)
    sock.sQpush8(1);         // version LE low byte
    sock.sQpush8(0);         //            LE high byte
    sock.sQpush8(0x52);      // 'R'
    sock.sQpush8(0x53);      // 'S'
    sock.sQpush8(0x41);      // 'A'
    sock.sQpush8(0x31);      // '1'
    sock.sQpush16(0);        // sub-protocol 0 = key request (u16be)
    sock.sQpush16(0);        // padding (u16be)
    sock.flush();
}

function sendRSATunnelCredBlob(sock, encryptedCreds, rsaCt) {
    const blobSize = 2 + 4 + 2 + 128 + 2 + rsaCt.length;
    sock.sQpush32(blobSize);
    sock.sQpush8(1);         // version (u16le=1) low byte
    sock.sQpush8(0);         //                   high byte
    sock.sQpush8(0x52);      // 'R'
    sock.sQpush8(0x53);      // 'S'
    sock.sQpush8(0x41);      // 'A'
    sock.sQpush8(0x31);      // '1'
    sock.sQpush16(1);        // sub-protocol 1 (u16be)
    sock.sQpushBytes(encryptedCreds);
    // rsaLen as u16le
    sock.sQpush8(rsaCt.length & 0xFF);
    sock.sQpush8((rsaCt.length >> 8) & 0xFF);
    sock.sQpushBytes(rsaCt);
    sock.flush();
}

function buildEncryptedKeyPayload(keysym, down, timestamp) {
    const buf = new Uint8Array(16);
    const dv = new DataView(buf.buffer);
    buf[0] = 0xFF;
    buf[1] = down ? 1 : 0;
    dv.setUint32(2, keysym, false);       // keysym, big-endian
    dv.setUint32(6, timestamp, false);    // timestamp, big-endian
    // bytes 10-15: reserved/keycode/unicode = 0
    return buf;
}

// ===================================================================
//  EncryptedEvent key payload (16 bytes)
// ===================================================================
describe('EncryptedEvent key payload', () => {
    it('has correct structure for key-down', () => {
        const payload = buildEncryptedKeyPayload(0x0041, true, 0x12345678);
        strictEqual(payload[0], 0xFF, 'marker byte');
        strictEqual(payload[1], 1, 'down flag');
        // keysym big-endian at [2..5]
        deepStrictEqual(
            Array.from(payload.slice(2, 6)),
            [0x00, 0x00, 0x00, 0x41]
        );
        // timestamp big-endian at [6..9]
        deepStrictEqual(
            Array.from(payload.slice(6, 10)),
            [0x12, 0x34, 0x56, 0x78]
        );
        // reserved/keycode/unicode = zeros at [10..15]
        deepStrictEqual(
            Array.from(payload.slice(10, 16)),
            [0, 0, 0, 0, 0, 0]
        );
    });

    it('has correct structure for key-up', () => {
        const payload = buildEncryptedKeyPayload(0xFF51, false, 1);
        strictEqual(payload[0], 0xFF);
        strictEqual(payload[1], 0, 'up flag');
        deepStrictEqual(
            Array.from(payload.slice(2, 6)),
            [0x00, 0x00, 0xFF, 0x51]
        );
    });

    it('encrypts to 16 bytes via AES-ECB', () => {
        const key = hex('2b7e151628aed2a6abf7158809cf4f3c');
        const ecb = new AES128ECB(key);
        const payload = buildEncryptedKeyPayload(0x0041, true, 1000);
        const encrypted = ecb.encrypt(payload);
        strictEqual(encrypted.length, 16);
        // Verify roundtrip
        const decrypted = ecb.decrypt(encrypted);
        deepStrictEqual(decrypted, payload);
    });
});

// ===================================================================
//  EncryptedEvent message (0x10)
// ===================================================================
describe('EncryptedEvent message (0x10)', () => {
    it('has correct wire format: [0x10][flags][16 bytes encrypted]', () => {
        const sock = new MockSock();
        const encrypted = new Uint8Array(16);
        for (let i = 0; i < 16; i++) encrypted[i] = i + 0xA0;

        sendEncryptedEvent(sock, 0, encrypted);

        const bytes = sock.toBytes();
        strictEqual(bytes.length, 18, 'total message length');
        strictEqual(bytes[0], 0x10, 'message type');
        strictEqual(bytes[1], 0x00, 'flags');
        deepStrictEqual(
            Array.from(bytes.slice(2)),
            Array.from(encrypted)
        );
    });
});

// ===================================================================
//  SetEncryption (0x12) — cmd=1 (request)
// ===================================================================
describe('SetEncryption (0x12) cmd=1 request', () => {
    it('produces exact byte sequence', () => {
        const sock = new MockSock();
        sendSetEncryption(sock, 1);
        deepStrictEqual(
            sock.toBytes(),
            hex('12 00 00 01 00 01 00 01 00 00 00 01')
        );
    });

    it('has 12 bytes total', () => {
        const sock = new MockSock();
        sendSetEncryption(sock, 1);
        strictEqual(sock.data.length, 12);
    });
});

// ===================================================================
//  SetEncryption (0x12) — cmd=2 (acknowledge)
// ===================================================================
describe('SetEncryption (0x12) cmd=2 acknowledge', () => {
    it('produces exact byte sequence', () => {
        const sock = new MockSock();
        sendSetEncryption(sock, 2);
        deepStrictEqual(
            sock.toBytes(),
            hex('12 00 00 02 00 01 00 00')
        );
    });

    it('has 8 bytes total', () => {
        const sock = new MockSock();
        sendSetEncryption(sock, 2);
        strictEqual(sock.data.length, 8);
    });
});

// ===================================================================
//  RSATunnel key request (14 bytes after 0x21 type selection)
// ===================================================================
describe('RSATunnel key request', () => {
    it('produces exact byte sequence', () => {
        const sock = new MockSock();
        sendRSATunnelKeyRequest(sock);
        deepStrictEqual(
            sock.toBytes(),
            hex('00 00 00 0a 01 00 52 53 41 31 00 00 00 00')
        );
    });

    it('has 14 bytes total', () => {
        const sock = new MockSock();
        sendRSATunnelKeyRequest(sock);
        strictEqual(sock.data.length, 14);
    });

    it('payload length field = 10', () => {
        const sock = new MockSock();
        sendRSATunnelKeyRequest(sock);
        const bytes = sock.toBytes();
        const payloadLen = (bytes[0] << 24) | (bytes[1] << 16) |
                           (bytes[2] << 8) | bytes[3];
        strictEqual(payloadLen, 10);
    });

    it('version is 1 in little-endian', () => {
        const sock = new MockSock();
        sendRSATunnelKeyRequest(sock);
        const bytes = sock.toBytes();
        strictEqual(bytes[4], 1, 'LE low byte');
        strictEqual(bytes[5], 0, 'LE high byte');
    });

    it('magic is "RSA1"', () => {
        const sock = new MockSock();
        sendRSATunnelKeyRequest(sock);
        const bytes = sock.toBytes();
        const magic = String.fromCharCode(bytes[6], bytes[7], bytes[8], bytes[9]);
        strictEqual(magic, 'RSA1');
    });
});

// ===================================================================
//  RSATunnel credential blob
// ===================================================================
describe('RSATunnel credential blob', () => {
    it('has correct structure and blobSize', () => {
        // Use a known AES key to encrypt 128 bytes of credentials
        const aesKey = hex('000102030405060708090a0b0c0d0e0f');
        const ecb = new AES128ECB(aesKey);

        // Build 128-byte credential plaintext (user[64] + pass[64])
        const credsPt = new Uint8Array(128);
        const user = new TextEncoder().encode('admin');
        const pass = new TextEncoder().encode('secret');
        credsPt.set(user);
        credsPt.set(pass, 64);

        const encryptedCreds = ecb.encrypt(credsPt);
        strictEqual(encryptedCreds.length, 128);

        // Fake RSA ciphertext (in reality this would be PKCS#1 v1.5)
        const rsaCt = new Uint8Array(128);
        for (let i = 0; i < 128; i++) rsaCt[i] = i;

        const sock = new MockSock();
        sendRSATunnelCredBlob(sock, encryptedCreds, rsaCt);
        const bytes = sock.toBytes();

        // Verify blobSize field (u32be at offset 0)
        const blobSize = (bytes[0] << 24) | (bytes[1] << 16) |
                         (bytes[2] << 8) | bytes[3];
        const expectedBlobSize = 2 + 4 + 2 + 128 + 2 + rsaCt.length; // 266
        strictEqual(blobSize, expectedBlobSize);

        // Total wire bytes = 4 (blobSize field) + blobSize
        strictEqual(bytes.length, 4 + expectedBlobSize);

        // Version u16le = 1 at offset 4
        strictEqual(bytes[4], 1, 'version LE low');
        strictEqual(bytes[5], 0, 'version LE high');

        // Magic "RSA1" at offset 6
        const magic = String.fromCharCode(bytes[6], bytes[7], bytes[8], bytes[9]);
        strictEqual(magic, 'RSA1');

        // Sub-protocol u16be = 1 at offset 10
        strictEqual(bytes[10], 0x00);
        strictEqual(bytes[11], 0x01);

        // Encrypted credentials: 128 bytes at offset 12
        deepStrictEqual(
            Array.from(bytes.slice(12, 140)),
            Array.from(encryptedCreds)
        );

        // RSA ciphertext length u16le at offset 140
        strictEqual(bytes[140], rsaCt.length & 0xFF, 'rsaLen LE low');
        strictEqual(bytes[141], (rsaCt.length >> 8) & 0xFF, 'rsaLen LE high');

        // RSA ciphertext at offset 142
        deepStrictEqual(
            Array.from(bytes.slice(142)),
            Array.from(rsaCt)
        );
    });

    it('credentials roundtrip through AES-ECB', () => {
        const aesKey = hex('deadbeefcafebabe1122334455667788');
        const ecb = new AES128ECB(aesKey);

        const credsPt = new Uint8Array(128);
        new TextEncoder().encode('testuser').forEach((b, i) => { credsPt[i] = b; });
        new TextEncoder().encode('testpass').forEach((b, i) => { credsPt[64 + i] = b; });

        const encrypted = ecb.encrypt(credsPt);
        const decrypted = ecb.decrypt(encrypted);
        deepStrictEqual(decrypted, credsPt);
    });
});
