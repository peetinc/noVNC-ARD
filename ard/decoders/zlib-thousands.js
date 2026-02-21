/*
 * noVNC-ARD: ARD ArdThousands (encoding 1002) decoder.
 * 16-bit RGB555, zlib compressed.
 */

import Inflator from "../../noVNC/core/inflator.js";

export default class ArdThousandsDecoder {
    constructor() {
        this._zlib = new Inflator();
        this._length = 0;
    }

    decodeRect(x, y, width, height, sock, display, depth) {
        if ((width === 0) || (height === 0)) {
            return true;
        }

        if (this._length === 0) {
            if (sock.rQwait("ArdThousands", 4)) {
                return false;
            }

            this._length = sock.rQshift32();
        }

        if (sock.rQwait("ArdThousands", this._length)) {
            return false;
        }

        let data = new Uint8Array(sock.rQshiftBytes(this._length, false));
        this._length = 0;

        this._zlib.setInput(data);
        const rgb555 = this._zlib.inflate(width * height * 2);
        this._zlib.setInput(null);

        // Convert RGB555 (big-endian) to RGBA
        const pixels = new Uint8Array(width * height * 4);
        let pIdx = 0;
        for (let i = 0; i < width * height; i++) {
            const word = (rgb555[i * 2] << 8) | rgb555[i * 2 + 1];
            const r = (word >> 10) & 0x1f;
            const g = (word >> 5) & 0x1f;
            const b = word & 0x1f;
            // Scale 5-bit (0-31) to 8-bit (0-255)
            pixels[pIdx++] = (r << 3) | (r >> 2);
            pixels[pIdx++] = (g << 3) | (g >> 2);
            pixels[pIdx++] = (b << 3) | (b >> 2);
            pixels[pIdx++] = 255;
        }

        display.blitImage(x, y, width, height, pixels, 0);

        return true;
    }
}
