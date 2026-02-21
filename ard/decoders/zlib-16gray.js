/*
 * noVNC-ARD: ARD ArdGray16 (encoding 1001) decoder.
 * 4-bit grayscale (16 levels), zlib compressed.
 */

import Inflator from "../../noVNC/core/inflator.js";

export default class ArdGray16Decoder {
    constructor() {
        this._zlib = new Inflator();
        this._length = 0;
    }

    decodeRect(x, y, width, height, sock, display, depth) {
        if ((width === 0) || (height === 0)) {
            return true;
        }

        if (this._length === 0) {
            if (sock.rQwait("ArdGray16", 4)) {
                return false;
            }

            this._length = sock.rQshift32();
        }

        if (sock.rQwait("ArdGray16", this._length)) {
            return false;
        }

        let data = new Uint8Array(sock.rQshiftBytes(this._length, false));
        this._length = 0;

        const rowBytes = Math.ceil(width / 2);
        this._zlib.setInput(data);
        const gray4 = this._zlib.inflate(rowBytes * height);
        this._zlib.setInput(null);

        // Convert 4-bit grayscale (2 pixels per byte) to RGBA
        const pixels = new Uint8Array(width * height * 4);
        let pIdx = 0;
        for (let row = 0; row < height; row++) {
            const rowOff = row * rowBytes;
            for (let col = 0; col < width; col++) {
                const byteVal = gray4[rowOff + (col >> 1)];
                const nibble = (col & 1) === 0 ? (byteVal >> 4) : (byteVal & 0x0f);
                const v = nibble * 17;  // scale 0-15 to 0-255
                pixels[pIdx++] = v;
                pixels[pIdx++] = v;
                pixels[pIdx++] = v;
                pixels[pIdx++] = 255;
            }
        }

        display.blitImage(x, y, width, height, pixels, 0);

        return true;
    }
}
