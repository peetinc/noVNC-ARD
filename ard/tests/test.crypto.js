/*
 * Unit tests for ARD crypto primitives: AES-128, SHA-1, PKCS#1 DER parser
 *
 * Run: node --test ard/tests/test.crypto.js
 */

import { describe, it } from 'node:test';
import { deepStrictEqual, strictEqual } from 'node:assert';

import { AES128ECB, AES128CBC } from '../crypto/aes128.js';
import { SHA1 } from '../crypto/sha1.js';
import { parsePKCS1PublicKey } from '../crypto/pkcs1.js';

// Helper: hex string → Uint8Array
function hex(s) {
    const bytes = s.replace(/\s+/g, '').match(/.{2}/g);
    return new Uint8Array(bytes.map(b => parseInt(b, 16)));
}

// Helper: Uint8Array → hex string (for readable assertion messages)
function toHex(arr) {
    return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ===================================================================
//  AES-128-ECB
// ===================================================================
describe('AES-128-ECB', () => {
    // FIPS 197 Appendix B test vector
    const key = hex('2b7e151628aed2a6abf7158809cf4f3c');
    const pt  = hex('3243f6a8885a308d313198a2e0370734');
    const ct  = hex('3925841d02dc09fbdc118597196a0b32');

    it('encrypts single block (FIPS 197 Appendix B)', () => {
        const ecb = new AES128ECB(key);
        const result = ecb.encrypt(pt);
        deepStrictEqual(result, ct);
    });

    it('decrypts single block (FIPS 197 Appendix B)', () => {
        const ecb = new AES128ECB(key);
        const result = ecb.decrypt(ct);
        deepStrictEqual(result, pt);
    });

    it('roundtrips 3 blocks', () => {
        const ecb = new AES128ECB(key);
        const input = new Uint8Array(48);
        for (let i = 0; i < 48; i++) input[i] = i;
        const encrypted = ecb.encrypt(input);
        strictEqual(encrypted.length, 48);
        const decrypted = ecb.decrypt(encrypted);
        deepStrictEqual(decrypted, input);
    });

    it('returns null on 15-byte input', () => {
        const ecb = new AES128ECB(key);
        strictEqual(ecb.encrypt(new Uint8Array(15)), null);
        strictEqual(ecb.decrypt(new Uint8Array(15)), null);
    });

    it('returns null on 17-byte input', () => {
        const ecb = new AES128ECB(key);
        strictEqual(ecb.encrypt(new Uint8Array(17)), null);
        strictEqual(ecb.decrypt(new Uint8Array(17)), null);
    });
});

// ===================================================================
//  AES-128-CBC — NIST SP 800-38A test vectors
// ===================================================================
describe('AES-128-CBC', () => {
    // NIST SP 800-38A F.2.1 / F.2.2
    const key = hex('2b7e151628aed2a6abf7158809cf4f3c');
    const iv  = hex('000102030405060708090a0b0c0d0e0f');
    const pt  = hex(
        '6bc1bee22e409f96e93d7e117393172a' +
        'ae2d8a571e03ac9c9eb76fac45af8e51' +
        '30c81c46a35ce411e5fbc1191a0a52ef' +
        'f69f2445df4f9b17ad2b417be66c3710'
    );
    const ct  = hex(
        '7649abac8119b246cee98e9b12e9197d' +
        '5086cb9b507219ee95db113a917678b2' +
        '73bed6b8e3c1743b7116e69e22229516' +
        '3ff1caa1681fac09120eca307586e1a7'
    );

    it('encrypts 4 blocks (NIST SP 800-38A F.2.1)', () => {
        const cbc = new AES128CBC(key);
        const result = cbc.encrypt(pt, iv);
        deepStrictEqual(result.data, ct);
    });

    it('decrypts 4 blocks (NIST SP 800-38A F.2.2)', () => {
        const cbc = new AES128CBC(key);
        const result = cbc.decrypt(ct, iv);
        deepStrictEqual(result.data, pt);
    });

    it('returned IV equals last ciphertext block', () => {
        const cbc = new AES128CBC(key);
        const result = cbc.encrypt(pt, iv);
        // Last ciphertext block is bytes [48..63]
        const lastBlock = ct.slice(48, 64);
        deepStrictEqual(result.iv, lastBlock);
    });

    it('roundtrips with IV chaining', () => {
        const cbc = new AES128CBC(key);
        const blockA = new Uint8Array(16);
        const blockB = new Uint8Array(16);
        for (let i = 0; i < 16; i++) { blockA[i] = i; blockB[i] = i + 0x20; }

        // Encrypt A, chain IV to B
        const encA = cbc.encrypt(blockA, iv);
        const encB = cbc.encrypt(blockB, encA.iv);

        // Decrypt both using same IV chain
        const decA = cbc.decrypt(encA.data, iv);
        const decB = cbc.decrypt(encB.data, decA.iv);

        deepStrictEqual(decA.data, blockA);
        deepStrictEqual(decB.data, blockB);
    });

    it('returns null on misaligned input', () => {
        const cbc = new AES128CBC(key);
        strictEqual(cbc.encrypt(new Uint8Array(15), iv), null);
        strictEqual(cbc.decrypt(new Uint8Array(17), iv), null);
    });
});

// ===================================================================
//  SHA-1 — RFC 3174 test vectors
// ===================================================================
describe('SHA-1', () => {
    it('"abc" → a9993e36... (RFC 3174 test 1)', () => {
        const input = new TextEncoder().encode('abc');
        const result = SHA1(input);
        strictEqual(toHex(result), 'a9993e364706816aba3e25717850c26c9cd0d89d');
    });

    it('empty input → da39a3ee...', () => {
        const result = SHA1(new Uint8Array(0));
        strictEqual(toHex(result), 'da39a3ee5e6b4b0d3255bfef95601890afd80709');
    });

    it('56-byte string → 84983e44... (RFC 3174 test 2)', () => {
        const input = new TextEncoder().encode(
            'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'
        );
        strictEqual(input.length, 56);
        const result = SHA1(input);
        strictEqual(toHex(result), '84983e441c3bd26ebaae4aa1f95129e5e54670f1');
    });
});

// ===================================================================
//  PKCS#1 DER Parser
// ===================================================================
describe('PKCS#1 DER Parser', () => {
    // Hand-constructed DER for a tiny RSA key (64-bit modulus, e=65537)
    // This is a valid PKCS#1 RSAPublicKey structure:
    //   SEQUENCE {
    //     INTEGER (n = 0x00B3510A2F7788C1)  -- with leading 0x00 for sign
    //     INTEGER (e = 0x010001)
    //   }
    const n_bytes = hex('b3510a2f7788c1');  // 7-byte modulus (no leading zero)
    const e_bytes = hex('010001');

    // Build bare PKCS#1: SEQUENCE { INTEGER n, INTEGER e }
    function buildPKCS1(n, e) {
        // INTEGER for n: tag(02) + len + optional-zero + n
        const nNeedsZero = (n[0] & 0x80) !== 0;
        const nIntLen = n.length + (nNeedsZero ? 1 : 0);
        const nInt = [0x02, nIntLen];
        if (nNeedsZero) nInt.push(0x00);
        nInt.push(...n);

        // INTEGER for e: tag(02) + len + e
        const eInt = [0x02, e.length, ...e];

        // SEQUENCE: tag(30) + len + contents
        const seqContents = [...nInt, ...eInt];
        return new Uint8Array([0x30, seqContents.length, ...seqContents]);
    }

    // Build SPKI wrapper around PKCS#1
    function buildSPKI(pkcs1) {
        // AlgorithmIdentifier for RSA: SEQUENCE { OID 1.2.840.113549.1.1.1, NULL }
        const algId = hex('300d06092a864886f70d0101010500');

        // BIT STRING: tag(03) + len + unused-bits(00) + pkcs1
        const bitStr = [0x03, pkcs1.length + 1, 0x00, ...pkcs1];

        // Outer SEQUENCE: tag(30) + len + algId + bitStr
        const seqContents = [...algId, ...bitStr];
        const totalLen = seqContents.length;

        // Use long-form length if >= 128
        if (totalLen < 128) {
            return new Uint8Array([0x30, totalLen, ...seqContents]);
        }
        return new Uint8Array([0x30, 0x81, totalLen, ...seqContents]);
    }

    it('parses bare PKCS#1 format', () => {
        const der = buildPKCS1(n_bytes, e_bytes);
        const key = parsePKCS1PublicKey(der);
        deepStrictEqual(key.n, n_bytes);
        deepStrictEqual(key.e, e_bytes);
    });

    it('parses SPKI-wrapped format', () => {
        const pkcs1 = buildPKCS1(n_bytes, e_bytes);
        const spki = buildSPKI(pkcs1);
        const key = parsePKCS1PublicKey(spki);
        deepStrictEqual(key.n, n_bytes);
        deepStrictEqual(key.e, e_bytes);
    });

    it('strips leading zero sign byte from modulus', () => {
        // Build a modulus with high bit set (needs 0x00 prefix in DER)
        const nHighBit = hex('ff0102030405060708');
        const der = buildPKCS1(nHighBit, e_bytes);
        const key = parsePKCS1PublicKey(der);
        // Parser should strip the 0x00 and return the raw modulus
        deepStrictEqual(key.n, nHighBit);
    });
});
