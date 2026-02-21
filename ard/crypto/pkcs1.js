/*
 * noVNC-ARD: PKCS#1 DER Public Key Parser
 *
 * Parses a DER-encoded RSA public key (PKCS#1 or SPKI format)
 * and returns { n, e } as Uint8Arrays.
 */

export function parsePKCS1PublicKey(der) {
    let pos = 0;

    function readLength() {
        let len = der[pos++];
        if (len & 0x80) {
            const numBytes = len & 0x7f;
            len = 0;
            for (let i = 0; i < numBytes; i++) {
                len = (len << 8) | der[pos++];
            }
        }
        return len;
    }

    function readInteger() {
        if (der[pos++] !== 0x02) {
            throw new Error("Expected INTEGER tag in DER");
        }
        let len = readLength();
        // Strip leading zero sign byte
        if (der[pos] === 0x00 && (der[pos + 1] & 0x80)) {
            pos++;
            len--;
        }
        const value = der.slice(pos, pos + len);
        pos += len;
        return value;
    }

    // Outer SEQUENCE
    if (der[pos++] !== 0x30) {
        throw new Error("Expected SEQUENCE tag in DER");
    }
    readLength();

    // Check if SPKI format (starts with SEQUENCE for AlgorithmIdentifier)
    // or bare PKCS#1 (starts with INTEGER for modulus)
    if (der[pos] === 0x30) {
        // SPKI: skip AlgorithmIdentifier
        pos++;
        const algLen = readLength();
        pos += algLen;

        // BIT STRING containing the PKCS#1 key
        if (der[pos++] !== 0x03) {
            throw new Error("Expected BIT STRING tag in SPKI");
        }
        readLength();
        pos++; // skip unused-bits byte

        // Inner SEQUENCE
        if (der[pos++] !== 0x30) {
            throw new Error("Expected inner SEQUENCE tag in SPKI");
        }
        readLength();
    }

    const n = readInteger(); // modulus
    const e = readInteger(); // public exponent

    return {
        n: new Uint8Array(n),
        e: new Uint8Array(e)
    };
}
