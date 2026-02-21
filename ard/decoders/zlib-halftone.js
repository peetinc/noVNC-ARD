/*
 * noVNC-ARD: ARD ArdHalftone (encoding 1000) decoder.
 * 1-bit monochrome (halftone dithered), zlib compressed.
 */

import Inflator from "../../noVNC/core/inflator.js";

export default class ArdHalftoneDecoder {
    constructor() {
        this._zlib = new Inflator();
        this._length = 0;
    }

    decodeRect(x, y, width, height, sock, display, depth) {
        if ((width === 0) || (height === 0)) {
            return true;
        }

        if (this._length === 0) {
            if (sock.rQwait("ArdHalftone", 4)) {
                return false;
            }

            this._length = sock.rQshift32();
        }

        if (sock.rQwait("ArdHalftone", this._length)) {
            return false;
        }

        let data = new Uint8Array(sock.rQshiftBytes(this._length, false));
        this._length = 0;

        const rowBytes = Math.ceil(width / 8);
        this._zlib.setInput(data);
        const mono = this._zlib.inflate(rowBytes * height);
        this._zlib.setInput(null);

        // Convert 1-bit monochrome (MSB first) to RGBA
        const pixels = new Uint8Array(width * height * 4);
        let pIdx = 0;
        for (let row = 0; row < height; row++) {
            const rowOff = row * rowBytes;
            for (let col = 0; col < width; col++) {
                const bit = (mono[rowOff + (col >> 3)] >> (7 - (col & 7))) & 1;
                const v = bit ? 255 : 0;
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
