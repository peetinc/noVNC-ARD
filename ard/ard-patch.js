/*
 * noVNC-ARD: ARD Protocol Monkey-Patch
 *
 * Patches the RFB prototype to add Apple Remote Desktop protocol support.
 * Import this module to apply patches; it self-applies on load.
 *
 * Layer 1: Protocol scaffolding — detection, init, message dispatch,
 *          R/B swap, encoding negotiation. No feature implementations.
 */

import RFB from '../noVNC/core/rfb.js';
import * as Log from '../noVNC/core/util/logging.js';
import { decodeUTF8 } from '../noVNC/core/util/strings.js';
import { encodings } from '../noVNC/core/encodings.js';
import {
    clientInitARD,
    serverFlagSessionSelect,
    serverMsgTypeAck,
    serverMsgTypeNOP,
    serverMsgTypeStateChange,
    serverMsgTypeClipboard,
    serverMsgTypeDragEvent,
    serverMsgTypeDisplayInfo2,
    pseudoEncodingArdCursorPos,
} from './ard-constants.js';

// ===== Save original methods =====

const _origNegotiateProtocolVersion = RFB.prototype._negotiateProtocolVersion;
const _origInitMsg = RFB.prototype._initMsg;
const _origNegotiateServerInit = RFB.prototype._negotiateServerInit;
const _origSendEncodings = RFB.prototype._sendEncodings;
const _origNormalMsg = RFB.prototype._normalMsg;
const _origHandleRect = RFB.prototype._handleRect;
const _origHandleSecurityResult = RFB.prototype._handleSecurityResult;

// ===== (a) Protocol Version Detection =====
//
// Peek at the server version string before upstream consumes it.
// If 003.889, set the ARD flag and initialize ARD state.

RFB.prototype._negotiateProtocolVersion = function () {
    // Need 12 bytes for version string
    if (this._sock.rQlen() >= 12) {
        const versionBytes = this._sock.rQpeekBytes(12);
        const sversion = String.fromCharCode.apply(null, versionBytes).substr(4, 7);
        if (sversion === '003.889') {
            // Initialize ARD state on first detection
            this._rfbAppleARD = true;
            this._ardServerFlags = 0;
            this._ardCapabilityBitmap = null;
            this._ardSessionSelectNeeded = false;
            this._ardQualityPreset = 'thousands';
            this._ardEncryptionEnabled = false;
            this._ardClipboardSessionId = 0;
            Log.Info("ARD: Apple Remote Desktop server detected (003.889)");
        }
    }
    return _origNegotiateProtocolVersion.call(this);
};

// ===== (b) ClientInit — send 0xC1 for ARD =====

RFB.prototype._initMsg = function () {
    if (this._rfbInitState === 'ClientInitialisation' && this._rfbAppleARD) {
        this._sock.sQpush8(clientInitARD);
        this._sock.flush();
        this._rfbInitState = 'ServerInitialisation';
        Log.Info("ARD: Sent ClientInit 0xC1 (Shared + Select + Enhanced)");
        return true;
    }
    return _origInitMsg.call(this);
};

// ===== (c) ServerInit — parse Apple extension from name field =====

RFB.prototype._negotiateServerInit = function () {
    if (!this._rfbAppleARD) {
        return _origNegotiateServerInit.call(this);
    }

    // ARD ServerInit: standard 24-byte header + extended name field
    if (this._sock.rQwait("server initialization", 24)) { return false; }

    const width = this._sock.rQshift16();
    const height = this._sock.rQshift16();

    // Pixel format (16 bytes) — read and discard, we set our own
    this._sock.rQshift8();   // bpp
    this._sock.rQshift8();   // depth
    this._sock.rQshift8();   // big-endian
    this._sock.rQshift8();   // true-color
    this._sock.rQshift16();  // red-max
    this._sock.rQshift16();  // green-max
    this._sock.rQshift16();  // blue-max
    this._sock.rQshift8();   // red-shift
    this._sock.rQshift8();   // green-shift
    this._sock.rQshift8();   // blue-shift
    this._sock.rQskipBytes(3); // padding

    const nameLength = this._sock.rQshift32();
    if (this._sock.rQwait('server init name', nameLength, 24)) { return false; }

    // Parse Apple extension embedded in name field.
    // Apple servers put a 22-byte prefix (2 NUL marker + 4 flags + 16 capability)
    // before the actual machine name.
    let name;
    if (nameLength >= 22) {
        const marker = this._sock.rQshift16();
        if (marker === 0) {
            this._ardServerFlags = this._sock.rQshift32();
            this._ardCapabilityBitmap = this._sock.rQshiftBytes(16);
            this._ardSessionSelectNeeded = !!(this._ardServerFlags & serverFlagSessionSelect);

            const nameBytes = nameLength - 22;
            if (nameBytes > 0) {
                name = decodeUTF8(this._sock.rQshiftStr(nameBytes), true);
            } else {
                name = "";
            }

            Log.Info("ARD: Extended ServerInit — flags=0x" +
                     this._ardServerFlags.toString(16) +
                     ", sessionSelect=" + this._ardSessionSelectNeeded +
                     ", name=" + name);
        } else {
            // First 2 bytes weren't NUL marker — treat as raw name
            const remaining = nameLength - 2;
            const hi = (marker >> 8) & 0xff;
            const lo = marker & 0xff;
            name = decodeUTF8(
                String.fromCharCode(hi, lo) + this._sock.rQshiftStr(remaining),
                true
            );
        }
    } else {
        name = decodeUTF8(this._sock.rQshiftStr(nameLength), true);
    }

    Log.Info("ARD: Screen " + width + "x" + height + ", name: " + name);

    this._setDesktopName(name);
    this._resize(width, height);

    if (!this._viewOnly) {
        this._keyboard.grab();
        this._asyncClipboard.grab();
    }

    this._fbDepth = 24;

    // Send pixel format (upstream default: 32bpp, RedShift=0)
    // ARD servers respect SetPixelFormat for standard encodings.
    // ARD-specific decoders (Layer 2+) handle their own color conversion.
    RFB.messages.pixelFormat(this._sock, this._fbDepth, true);
    this._sendEncodings();

    // CRITICAL: Never send FBUpdateRequest with 0x0 dimensions —
    // causes screensharingd to hang in zlib deflate infinite loop
    if (width > 0 && height > 0) {
        RFB.messages.fbUpdateRequest(this._sock, false, 0, 0, width, height);
    } else {
        Log.Warn("ARD: Server reported 0x0 dimensions, deferring FBUpdateRequest");
    }

    this._updateConnectionState('connected');
    return true;
};

// ===== (d) Encoding negotiation =====

RFB.prototype._sendEncodings = function () {
    if (!this._rfbAppleARD) {
        return _origSendEncodings.call(this);
    }

    const encs = [];

    // Data encodings — standard only for Layer 1
    // (ARD-specific decoders like ArdThousands added in Layer 2)
    encs.push(encodings.encodingCopyRect);
    encs.push(encodings.encodingZlib);
    encs.push(encodings.encodingZRLE);
    encs.push(encodings.encodingHextile);
    encs.push(encodings.encodingRRE);
    encs.push(encodings.encodingRaw);

    // ARD pseudo-encodings (safe to handle in Layer 1)
    encs.push(pseudoEncodingArdCursorPos);  // 1100 — no payload

    // Standard pseudo-encodings
    encs.push(encodings.pseudoEncodingDesktopSize);
    encs.push(encodings.pseudoEncodingLastRect);
    encs.push(encodings.pseudoEncodingCursor);

    RFB.messages.clientEncodings(this._sock, encs);
};

// ===== (e) S→C message dispatch =====

RFB.prototype._normalMsg = function () {
    if (this._rfbAppleARD && this._FBU.rects === 0) {
        if (this._sock.rQwait("msg type", 1)) { return false; }
        const msgType = this._sock.rQpeek8();

        switch (msgType) {
            case serverMsgTypeAck:   // 0x04 — zero payload
                this._sock.rQskipBytes(1);
                Log.Debug("ARD: ServerAck");
                return true;

            case serverMsgTypeNOP:   // 0x07 — zero payload
                this._sock.rQskipBytes(1);
                return true;

            case serverMsgTypeStateChange:  // 0x14
                return this._ardHandleStateChange();

            case serverMsgTypeClipboard:    // 0x1f
                return this._ardHandleServerClipboard();

            case serverMsgTypeDragEvent:    // 0x20
                return this._ardHandleServerDrag();

            case serverMsgTypeDisplayInfo2: // 0x51
                return this._ardHandleDisplayInfo2Msg();
        }
        // Not an ARD-specific type — fall through to upstream
    }
    return _origNormalMsg.call(this);
};

// ===== (f) ARD S→C message handlers (stubs) =====

// StateChange: [type(1)][pad(1)][size(2)=0x0004][flags(2)][status(2)]
RFB.prototype._ardHandleStateChange = function () {
    if (this._sock.rQwait("StateChange", 8)) { return false; }

    this._sock.rQskipBytes(1); // type (already peeked)
    this._sock.rQskipBytes(1); // padding
    this._sock.rQskipBytes(2); // size
    const flags = this._sock.rQshift16();
    const status = this._sock.rQshift16();

    Log.Info("ARD: StateChange — status=" + status + ", flags=0x" + flags.toString(16));

    // Layer 2+ will dispatch on status codes (clipboard, sleep/wake, etc.)
    return true;
};

// ServerClipboard: [type(1)][format(1)][reserved(2)][sessionID(4)][uncompSize(4)][compSize(4)][zlib...]
RFB.prototype._ardHandleServerClipboard = function () {
    if (this._sock.rQwait("ServerClipboard header", 16)) { return false; }

    // Peek at compressed size to know total message length
    const headerBytes = this._sock.rQpeekBytes(16);
    const compressedSize = ((headerBytes[12] << 24) | (headerBytes[13] << 16) |
                            (headerBytes[14] << 8)  |  headerBytes[15]) >>> 0;

    if (this._sock.rQwait("ServerClipboard payload", 16 + compressedSize)) { return false; }

    // Consume entire message
    this._sock.rQskipBytes(1); // type
    this._sock.rQskipBytes(1); // format
    this._sock.rQskipBytes(2); // reserved
    const sessionId = this._sock.rQshift32();
    this._sock.rQskipBytes(4); // uncompressed size
    this._sock.rQskipBytes(4); // compressed size
    this._sock.rQskipBytes(compressedSize); // zlib payload

    this._ardClipboardSessionId = sessionId;
    Log.Debug("ARD: ServerClipboard — sessionId=" + sessionId +
              ", compSize=" + compressedSize + " (skipped, Layer 2)");
    return true;
};

// ServerDragEvent: [type(1)][sessionID(4)][extraSize(4)][extra...]
RFB.prototype._ardHandleServerDrag = function () {
    if (this._sock.rQwait("ServerDrag header", 9)) { return false; }

    const headerBytes = this._sock.rQpeekBytes(9);
    const extraSize = (headerBytes[5] << 24) | (headerBytes[6] << 16) |
                      (headerBytes[7] << 8)  |  headerBytes[8];

    if (this._sock.rQwait("ServerDrag payload", 9 + extraSize)) { return false; }

    this._sock.rQskipBytes(9 + extraSize);
    Log.Debug("ARD: ServerDragEvent — extraSize=" + extraSize + " (skipped, Layer 2)");
    return true;
};

// DisplayInfo2 message: [type(1)][payloadSize(2)][payload...]
RFB.prototype._ardHandleDisplayInfo2Msg = function () {
    if (this._sock.rQwait("DisplayInfo2Msg header", 3)) { return false; }

    const headerBytes = this._sock.rQpeekBytes(3);
    const payloadSize = (headerBytes[1] << 8) | headerBytes[2];

    if (this._sock.rQwait("DisplayInfo2Msg payload", 3 + payloadSize)) { return false; }

    this._sock.rQskipBytes(3 + payloadSize);
    Log.Debug("ARD: DisplayInfo2 message — size=" + payloadSize + " (skipped, Layer 2)");
    return true;
};

// ===== (g) FBU pseudo-encoding dispatch =====

RFB.prototype._handleRect = function () {
    if (this._rfbAppleARD) {
        switch (this._FBU.encoding) {
            case pseudoEncodingArdCursorPos:  // 1100 — no payload
                Log.Debug("ARD: CursorPos — x=" + this._FBU.x + ", y=" + this._FBU.y);
                return true;

            // Layer 2+ will add handlers for other ARD encodings here
        }
    }
    return _origHandleRect.call(this);
};

// ===== (h) SecurityResult — skip SecurityReason for ARD =====
//
// ARD does NOT send a SecurityReason string after a failed SecurityResult.
// Upstream expects one for version >= 3.8, which would stall forever.

RFB.prototype._handleSecurityResult = function () {
    if (!this._rfbAppleARD) {
        return _origHandleSecurityResult.call(this);
    }

    if (this._sock.rQwait('VNC auth response ', 4)) { return false; }

    const status = this._sock.rQshift32();

    if (status === 0) {
        this._rfbInitState = 'ClientInitialisation';
        Log.Debug('ARD: Authentication OK');
        return true;
    } else {
        // ARD servers don't send SecurityReason — fail immediately
        this.dispatchEvent(new CustomEvent(
            "securityfailure",
            { detail: { status: status } }));
        return this._fail("ARD authentication failed (status " + status + ")");
    }
};

Log.Info("ARD: Protocol patch applied to RFB.prototype");
