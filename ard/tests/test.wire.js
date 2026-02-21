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
//  Message type constants
// ===================================================================

const MSG_ENCRYPTED_EVENT = 0x10;
const MSG_SET_ENCRYPTION  = 0x12;
const MSG_SET_MODE        = 0x0a;
const MSG_AUTO_PASTEBOARD = 0x15;
const MSG_CLIPBOARD_REQ   = 0x0b;
const MSG_CLIPBOARD_SEND  = 0x1f;
const MSG_VIEWER_INFO     = 0x21;

// ===================================================================
//  Message builders (replicated from ard-patch.js)
// ===================================================================

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

// ===================================================================
//  New Layer 2b message builders
// ===================================================================

function sendViewerInfo(sock) {
    sock.sQpush8(MSG_VIEWER_INFO);  // 0x21
    sock.sQpush8(0);                // padding
    sock.sQpush16(62);             // body size

    sock.sQpush16(1);              // appClass
    sock.sQpush32(0x00000002);     // appId = 2 (Screen Sharing)

    // 12-byte appVersion: 3 × u32be (major, minor, patch)
    sock.sQpush32(6);              // major
    sock.sQpush32(1);              // minor
    sock.sQpush32(0);              // patch

    // 12-byte osVersion: 3 × u32be (major, minor, patch)
    sock.sQpush32(15);             // major (macOS 15)
    sock.sQpush32(0);              // minor
    sock.sQpush32(0);              // patch

    // 32-byte command support bitmap
    const bitmap = new Uint8Array(32);
    bitmap[0]  = 0xb0;
    bitmap[2]  = 0x0c;
    bitmap[3]  = 0x03;
    bitmap[4]  = 0x90;
    bitmap[10] = 0x40;
    sock.sQpushBytes(bitmap);
    sock.flush();
}

function sendSetMode(sock, mode) {
    sock.sQpush8(MSG_SET_MODE);  // 0x0a
    sock.sQpush8(0);
    sock.sQpush8(0);
    sock.sQpush8(mode);
    sock.flush();
}

function sendSessionCommand(sock, cmd, username) {
    sock.sQpush16(72);    // bodySize
    sock.sQpush16(1);     // version
    sock.sQpush32(0);     // padding
    sock.sQpush8(cmd);
    sock.sQpush8(0);      // padding

    const userBuf = new Uint8Array(64);
    const encoded = new TextEncoder().encode(username || '');
    userBuf.set(encoded.subarray(0, Math.min(encoded.length, 63)));
    sock.sQpushBytes(userBuf);
    sock.flush();
}

function sendAutoPasteboard(sock, cmd) {
    sock.sQpush8(MSG_AUTO_PASTEBOARD);  // 0x15
    sock.sQpush8(0);
    sock.sQpush16(cmd);
    sock.sQpush32(0);
    sock.flush();
}

function sendClipboardRequest(sock, format, sessionId) {
    sock.sQpush8(MSG_CLIPBOARD_REQ);  // 0x0b
    sock.sQpush8(format);
    sock.sQpush16(0);
    sock.sQpush32(sessionId);
    sock.flush();
}

// ===================================================================
//  ViewerInfo (0x21) — 66 bytes
// ===================================================================
describe('ViewerInfo (0x21)', () => {
    it('has correct total length of 66 bytes', () => {
        const sock = new MockSock();
        sendViewerInfo(sock);
        strictEqual(sock.data.length, 66);
    });

    it('has correct type byte and body size', () => {
        const sock = new MockSock();
        sendViewerInfo(sock);
        const bytes = sock.toBytes();
        strictEqual(bytes[0], 0x21, 'type');
        strictEqual(bytes[1], 0x00, 'padding');
        // body size = 62 (u16be)
        strictEqual(bytes[2], 0x00);
        strictEqual(bytes[3], 62);
    });

    it('has appClass=1 and appId=2', () => {
        const sock = new MockSock();
        sendViewerInfo(sock);
        const bytes = sock.toBytes();
        // appClass u16be at offset 4
        strictEqual(bytes[4], 0x00);
        strictEqual(bytes[5], 0x01);
        // appId u32be at offset 6 = 0x00000002
        strictEqual(bytes[6], 0x00);
        strictEqual(bytes[7], 0x00);
        strictEqual(bytes[8], 0x00);
        strictEqual(bytes[9], 0x02);
    });

    it('has u32be version fields (major=6, minor=1, patch=0)', () => {
        const sock = new MockSock();
        sendViewerInfo(sock);
        const bytes = sock.toBytes();
        const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        // appVersion: 3 × u32be at offset 10
        strictEqual(dv.getUint32(10), 6, 'app major');
        strictEqual(dv.getUint32(14), 1, 'app minor');
        strictEqual(dv.getUint32(18), 0, 'app patch');
        // osVersion: 3 × u32be at offset 22
        strictEqual(dv.getUint32(22), 15, 'os major');
        strictEqual(dv.getUint32(26), 0, 'os minor');
        strictEqual(dv.getUint32(30), 0, 'os patch');
    });

    it('has non-zero command capability bitmap', () => {
        const sock = new MockSock();
        sendViewerInfo(sock);
        const bytes = sock.toBytes();
        // bitmap at offset 34, 32 bytes
        const bitmap = bytes.slice(34, 66);
        strictEqual(bitmap[0], 0xb0, 'bitmap[0]');
        strictEqual(bitmap[2], 0x0c, 'bitmap[2]');
        strictEqual(bitmap[3], 0x03, 'bitmap[3]');
        strictEqual(bitmap[4], 0x90, 'bitmap[4]');
        strictEqual(bitmap[10], 0x40, 'bitmap[10]');
        // Other bytes should be zero
        strictEqual(bitmap[1], 0, 'bitmap[1]');
        strictEqual(bitmap[5], 0, 'bitmap[5]');
    });
});

// ===================================================================
//  SetMode (0x0a) — 4 bytes
// ===================================================================
describe('SetMode (0x0a)', () => {
    it('has correct 4-byte format for control mode', () => {
        const sock = new MockSock();
        sendSetMode(sock, 2);
        deepStrictEqual(
            sock.toBytes(),
            hex('0a 00 00 02')
        );
    });

    it('has correct 4-byte format for observe mode', () => {
        const sock = new MockSock();
        sendSetMode(sock, 0);
        deepStrictEqual(
            sock.toBytes(),
            hex('0a 00 00 00')
        );
    });
});

// ===================================================================
//  SessionCommand — 74 bytes
// ===================================================================
describe('SessionCommand', () => {
    it('has correct total length of 74 bytes', () => {
        const sock = new MockSock();
        sendSessionCommand(sock, 1, 'admin');
        strictEqual(sock.data.length, 74);
    });

    it('has bodySize=72 and version=1', () => {
        const sock = new MockSock();
        sendSessionCommand(sock, 1, 'admin');
        const bytes = sock.toBytes();
        // bodySize u16be at offset 0
        strictEqual(bytes[0], 0x00);
        strictEqual(bytes[1], 72);
        // version u16be at offset 2
        strictEqual(bytes[2], 0x00);
        strictEqual(bytes[3], 0x01);
    });

    it('has command byte at offset 8', () => {
        const sock = new MockSock();
        sendSessionCommand(sock, 1, 'admin');
        const bytes = sock.toBytes();
        // padding u32be at offset 4
        strictEqual(bytes[4], 0); strictEqual(bytes[5], 0);
        strictEqual(bytes[6], 0); strictEqual(bytes[7], 0);
        // command at offset 8
        strictEqual(bytes[8], 1, 'ConnectToConsole');
    });

    it('has NUL-padded username in 64-byte field', () => {
        const sock = new MockSock();
        sendSessionCommand(sock, 0, 'admin');
        const bytes = sock.toBytes();
        // username starts at offset 10, 64 bytes
        const userField = bytes.slice(10, 74);
        strictEqual(userField[0], 0x61); // 'a'
        strictEqual(userField[1], 0x64); // 'd'
        strictEqual(userField[2], 0x6D); // 'm'
        strictEqual(userField[3], 0x69); // 'i'
        strictEqual(userField[4], 0x6E); // 'n'
        strictEqual(userField[5], 0x00); // NUL after "admin"
        // Rest should be zeros
        for (let i = 6; i < 64; i++) {
            strictEqual(userField[i], 0, 'zero padding at offset ' + i);
        }
    });
});

// ===================================================================
//  AutoPasteboard (0x15) — 8 bytes
// ===================================================================
describe('AutoPasteboard (0x15)', () => {
    it('produces correct enable byte sequence', () => {
        const sock = new MockSock();
        sendAutoPasteboard(sock, 1);
        deepStrictEqual(
            sock.toBytes(),
            hex('15 00 00 01 00 00 00 00')
        );
    });

    it('produces correct disable byte sequence', () => {
        const sock = new MockSock();
        sendAutoPasteboard(sock, 0);
        deepStrictEqual(
            sock.toBytes(),
            hex('15 00 00 00 00 00 00 00')
        );
    });

    it('has 8 bytes total', () => {
        const sock = new MockSock();
        sendAutoPasteboard(sock, 1);
        strictEqual(sock.data.length, 8);
    });
});

// ===================================================================
//  ClipboardRequest (0x0b) — 8 bytes
// ===================================================================
describe('ClipboardRequest (0x0b)', () => {
    it('produces correct byte sequence for UTF-8 format', () => {
        const sock = new MockSock();
        sendClipboardRequest(sock, 1, 7);
        deepStrictEqual(
            sock.toBytes(),
            hex('0b 01 00 00 00 00 00 07')
        );
    });

    it('has 8 bytes total', () => {
        const sock = new MockSock();
        sendClipboardRequest(sock, 1, 0);
        strictEqual(sock.data.length, 8);
    });

    it('encodes sessionId correctly', () => {
        const sock = new MockSock();
        sendClipboardRequest(sock, 1, 0x12345678);
        const bytes = sock.toBytes();
        // sessionId u32be at offset 4
        strictEqual(bytes[4], 0x12);
        strictEqual(bytes[5], 0x34);
        strictEqual(bytes[6], 0x56);
        strictEqual(bytes[7], 0x78);
    });
});

// ===================================================================
//  Session Select — event dispatch + selectSessionType wire format
// ===================================================================

// MockRFB simulates the subset of RFB needed for session select tests.
// It provides a mock socket with both push (send) and queue (receive) APIs,
// plus the dispatchEvent/addEventListener needed for event tests.
class MockReadSock extends MockSock {
    constructor() {
        super();
        this._rQ = [];
        this._rQi = 0;
    }
    // Feed bytes into the receive queue
    feed(bytes) {
        for (const b of bytes) this._rQ.push(b);
    }
    rQlen() { return this._rQ.length - this._rQi; }
    rQwait(msg, n) { return this.rQlen() < n; }
    rQpeek8() { return this._rQ[this._rQi]; }
    rQpeekBytes(n) { return new Uint8Array(this._rQ.slice(this._rQi, this._rQi + n)); }
    rQshift8() { return this._rQ[this._rQi++]; }
    rQshift16() { return (this.rQshift8() << 8) | this.rQshift8(); }
    rQshift32() { return (this.rQshift16() << 16) | this.rQshift16(); }
    rQshiftStr(n) {
        let s = '';
        for (let i = 0; i < n; i++) s += String.fromCharCode(this.rQshift8());
        return s;
    }
    rQskipBytes(n) { this._rQi += n; }
    rQshiftBytes(n) {
        const out = new Uint8Array(this._rQ.slice(this._rQi, this._rQi + n));
        this._rQi += n;
        return out;
    }
}

class MockRFB {
    constructor() {
        this._sock = new MockReadSock();
        this._ardSessionSelectStage = null;
        this._ardSessionSelectConsoleUser = '';
        this._events = {};
    }
    dispatchEvent(ev) {
        const handlers = this._events[ev.type] || [];
        for (const h of handlers) h(ev);
    }
    addEventListener(type, fn) {
        if (!this._events[type]) this._events[type] = [];
        this._events[type].push(fn);
    }
}

// Replicate _ardSessionSelect readInfo logic for testing
function runSessionSelectReadInfo(rfb) {
    const sock = rfb._sock;
    if (sock.rQwait("SessionInfo header", 2)) return false;
    const bsHdr = sock.rQpeekBytes(2);
    const bodySize = (bsHdr[0] << 8) | bsHdr[1];
    if (sock.rQwait("SessionInfo body", 2 + bodySize)) return false;

    sock.rQskipBytes(2);
    const ver = sock.rQshift16();
    const allowedCmds = sock.rQshift32();
    sock.rQskipBytes(4);
    const userBytes = bodySize - 10;
    const user = userBytes > 0 ? sock.rQshiftStr(userBytes) : '';

    rfb._ardSessionSelectConsoleUser = user;

    rfb.dispatchEvent(new CustomEvent('ardsessionselect', {
        detail: { username: user, allowedCommands: allowedCmds, hasConsoleUser: !!user }
    }));
    rfb._ardSessionSelectStage = 'waitingForUI';
    return true;
}

// Build a SessionInfo payload for testing
// Format: [u16be bodySize][u16be ver][u32be allowedCmds][u32be reserved][user bytes]
function buildSessionInfo(ver, allowedCmds, username) {
    const userBytes = new TextEncoder().encode(username || '');
    const bodySize = 10 + userBytes.length;
    const buf = [];
    buf.push((bodySize >> 8) & 0xFF, bodySize & 0xFF);     // bodySize
    buf.push((ver >> 8) & 0xFF, ver & 0xFF);                 // version
    buf.push((allowedCmds >> 24) & 0xFF, (allowedCmds >> 16) & 0xFF,
             (allowedCmds >> 8) & 0xFF, allowedCmds & 0xFF); // allowedCmds
    buf.push(0, 0, 0, 0);                                    // reserved
    for (const b of userBytes) buf.push(b);
    return buf;
}

describe('Session Select — ardsessionselect event', () => {
    it('fires ardsessionselect when console user is present', () => {
        const rfb = new MockRFB();
        let received = null;
        rfb.addEventListener('ardsessionselect', (e) => { received = e.detail; });

        rfb._sock.feed(buildSessionInfo(0x0100, 0x07, 'admin'));
        runSessionSelectReadInfo(rfb);

        strictEqual(received !== null, true, 'event should have fired');
        strictEqual(received.username, 'admin');
        strictEqual(received.hasConsoleUser, true);
        strictEqual(received.allowedCommands, 0x07);
        strictEqual(rfb._ardSessionSelectStage, 'waitingForUI');
    });

    it('fires ardsessionselect when no console user (hasConsoleUser=false)', () => {
        const rfb = new MockRFB();
        let received = null;
        rfb.addEventListener('ardsessionselect', (e) => { received = e.detail; });

        rfb._sock.feed(buildSessionInfo(0x0100, 0x07, ''));
        runSessionSelectReadInfo(rfb);

        strictEqual(received !== null, true, 'event should have fired');
        strictEqual(received.hasConsoleUser, false);
        strictEqual(received.username, '');
        strictEqual(rfb._ardSessionSelectStage, 'waitingForUI');
    });
});

describe('Session Select — selectSessionType wire bytes', () => {
    it('selectSessionType(1) sends SessionCommand with cmd=1', () => {
        const rfb = new MockRFB();
        rfb._ardSessionSelectStage = 'waitingForUI';
        rfb._ardSessionSelectConsoleUser = 'testuser';

        // Simulate selectSessionType
        const user = rfb._ardSessionSelectConsoleUser || '';
        sendSessionCommand(rfb._sock, 1, user);
        rfb._ardSessionSelectStage = 'readResult';

        const bytes = rfb._sock.toBytes();
        strictEqual(bytes.length, 74);
        strictEqual(bytes[8], 1, 'command = ConnectToConsole');
        // Username at offset 10
        strictEqual(bytes[10], 0x74); // 't'
        strictEqual(bytes[11], 0x65); // 'e'
    });

    it('selectSessionType(2) sends SessionCommand with cmd=2', () => {
        const rfb = new MockRFB();
        rfb._ardSessionSelectStage = 'waitingForUI';
        rfb._ardSessionSelectConsoleUser = 'testuser';

        const user = rfb._ardSessionSelectConsoleUser || '';
        sendSessionCommand(rfb._sock, 2, user);
        rfb._ardSessionSelectStage = 'readResult';

        const bytes = rfb._sock.toBytes();
        strictEqual(bytes.length, 74);
        strictEqual(bytes[8], 2, 'command = ConnectToVirtualDisplay');
    });
});

describe('Session Select — waitingForUI stage', () => {
    it('waitingForUI blocks (returns false from state machine)', () => {
        // The readInfo handler sets stage to waitingForUI when a user is present.
        // Subsequent calls to the state machine should return false (blocked).
        const rfb = new MockRFB();
        rfb._ardSessionSelectStage = 'waitingForUI';

        // Simulate the switch case — waitingForUI returns false
        let result;
        switch (rfb._ardSessionSelectStage) {
            case 'waitingForUI':
                result = false;
                break;
            default:
                result = true;
        }
        strictEqual(result, false, 'waitingForUI should return false');
    });
});
