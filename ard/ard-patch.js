/*
 * noVNC-ARD: ARD Protocol Monkey-Patch
 *
 * Patches the RFB prototype to add Apple Remote Desktop protocol support.
 * Import this module to apply patches; it self-applies on load.
 *
 * Layer 1: Protocol scaffolding — detection, init, message dispatch,
 *          encoding negotiation.
 * Layer 2a: EncryptedEvent (0x10), RSATunnel auth (type 33),
 *           Session Encryption (encoding 1103).
 * Layer 2b: Session Select, ViewerInfo/SetMode, StateChange dispatch,
 *           DisplayInfo, UserInfo, Clipboard, CursorAlpha,
 *           DeviceInfo, KeyboardInput, connection info panel.
 */

import RFB from '../noVNC/core/rfb.js';
import Websock from '../noVNC/core/websock.js';
import * as Log from '../noVNC/core/util/logging.js';
import { encodeUTF8, decodeUTF8 } from '../noVNC/core/util/strings.js';
import { encodings } from '../noVNC/core/encodings.js';
import legacyCrypto from '../noVNC/core/crypto/crypto.js';
import { RSACipher } from '../noVNC/core/crypto/rsa.js';
import Inflator from '../noVNC/core/inflator.js';
import Deflator from '../noVNC/core/deflator.js';

import { AES128ECB, AES128CBC } from './crypto/aes128.js';
import { parsePKCS1PublicKey } from './crypto/pkcs1.js';
import { SHA1 } from './crypto/sha1.js';

import {
    clientInitARD,
    securityTypeRSATunnel,
    serverFlagSessionSelect,
    serverMsgTypeAck,
    serverMsgTypeNOP,
    serverMsgTypeStateChange,
    serverMsgTypeClipboard,
    serverMsgTypeDragEvent,
    serverMsgTypeDisplayInfo2,
    pseudoEncodingArdCursorPos,
    pseudoEncodingArdDisplayInfo,
    pseudoEncodingArdUserInfo,
    pseudoEncodingArdSessionEncryption,
    pseudoEncodingArdCursorAlpha,
    pseudoEncodingArdDisplayInfo2,
    pseudoEncodingArdDeviceInfo,
    pseudoEncodingArdKeyboardInput,
    msgTypeEncryptedEvent,
    msgTypeSetEncryption,
    msgTypeViewerInfo,
    msgTypeAutoFBUpdate,
    msgTypeSetMode,
    msgTypeSetDisplay,
    msgTypeAutoPasteboard,
    msgTypeClipboardReq,
    msgTypeClipboardSend,
    stateLocalUserClosed,
    statePasteboardChanged,
    statePasteboardDataNeeded,
    stateTickle,
    stateSleep,
    stateWake,
    stateCursorHidden,
    stateCursorVisible,
    sessionCmdRequestConsole,
    sessionCmdConnectToConsole,
    sessionCmdConnectToVirtualDisplay,
    sessionStatusGranted,
    sessionStatusPending,
    sessionStatusPendingAlt,
    sessionStatusGrantedAfterPending,
    clipboardFormatUTF8,
} from './ard-constants.js';

// ===== Save original methods =====

const _origNegotiateSecurity = RFB.prototype._negotiateSecurity;
const _origNegotiateProtocolVersion = RFB.prototype._negotiateProtocolVersion;
const _origInitMsg = RFB.prototype._initMsg;
const _origNegotiateServerInit = RFB.prototype._negotiateServerInit;
const _origSendEncodings = RFB.prototype._sendEncodings;
const _origNormalMsg = RFB.prototype._normalMsg;
const _origHandleRect = RFB.prototype._handleRect;
const _origHandleSecurityResult = RFB.prototype._handleSecurityResult;
const _origSendKey = RFB.prototype.sendKey;
const _origIsSupportedSecurityType = RFB.prototype._isSupportedSecurityType;
const _origNegotiateAuthentication = RFB.prototype._negotiateAuthentication;

const _origClipboardPasteFrom = RFB.prototype.clipboardPasteFrom;

const _origWsFlush = Websock.prototype.flush;
const _origWsRecvMessage = Websock.prototype._recvMessage;

// ===================================================================
//  LAYER 1: Protocol Scaffolding
// ===================================================================

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
            this._ardClipboardSessionId = 0;

            // Session Select state
            this._ardSessionSelectStage = null;
            this._ardSessionSelectConsoleUser = '';
            this._ardSessionType = null;  // 1=ShareDisplay, 2=VirtualDisplay
            this._ardVirtualLogin = this._ardVirtualLogin ?? 1; // 0=always share, 1=show picker, 2=always virtual
            this._ardDeferredFBURequest = false;

            // Message dispatch state: tracks type byte across partial reads
            this._ardPendingMsgType = null;

            // Display/User info
            this._ardDisplays = [];
            this._ardRemoteUser = '';
            this._ardDeviceInfo = null;
            this._ardKeyboardInput = null;

            // Clipboard
            this._ardClipboardOutgoing = null;

            // Cursor
            this._ardCursorCache = new Map();
            this._ardCursorVisible = true;
            this._ardCurrentCursorId = -1;

            // Layer 2 state: encryption
            this._ardAuthKey = null;        // 16-byte AES key from auth
            this._ardECBCipher = null;      // Lazily-created AES128ECB
            this._ardEncryptionEnabled = false;
            this._ardPendingEncryption = null; // { key, iv } awaiting FBU completion
            this._ardSessionKey = null;
            this._ardSessionIV = null;

            // Encryption mode: 1=keystroke-only, 2=full tunnel (default)
            // Read from DOM dropdown if available, otherwise default to 2
            const ardEncEl = document.getElementById('noVNC_setting_ardEncryption');
            this._ardEncryptionMode = ardEncEl ? parseInt(ardEncEl.value, 10) : 2;

            // Layer 2 state: RSATunnel
            this._ardRSATunnelStage = 0;
            this._ardRSATunnelKey = null;   // Cached server RSA public key
            this._ardRSATunnelCreds = null; // Encrypted credential blob
            this._ardRSATunnelRSACt = null; // RSA ciphertext

            Log.Info("ARD: Apple Remote Desktop server detected (003.889)");

            // Handle version exchange ourselves — ARD requires echoing 003.889 exactly.
            // Upstream would send 003.008 (maps 003.889 → 3.8), which makes the server
            // treat us as a standard VNC client and skip Extended ServerInit.
            this._sock.rQshiftStr(12);  // consume version string
            this._rfbVersion = 3.8;
            this._sock.sQpushString("RFB 003.889\n");
            this._sock.flush();
            Log.Debug("ARD: Sent ProtocolVersion: 003.889");
            this._rfbInitState = 'Security';
            return true;
        }
    }
    return _origNegotiateProtocolVersion.call(this);
};

// ===== (a2) Security Type Preference =====
//
// ARD servers offer both type 30 (DH) and type 33 (RSATunnel).
// Upstream picks the first supported type from the server's list.
// We prefer type 33 (RSATunnel) when available — it's the stronger auth.

RFB.prototype._negotiateSecurity = function () {
    if (!this._rfbAppleARD || this._rfbVersion < 3.7) {
        return _origNegotiateSecurity.call(this);
    }

    // Peek: need 1 byte for count
    if (this._sock.rQwait("security type count", 1)) { return false; }
    const numTypes = this._sock.rQpeek8();
    if (this._sock.rQwait("security types", 1 + numTypes)) { return false; }

    this._sock.rQshift8(); // consume count
    if (numTypes === 0) {
        // Delegate to upstream for error handling (SecurityReason)
        // Put the byte back — actually we can't, so handle inline
        this._rfbInitState = "SecurityReason";
        this._securityContext = "no security types";
        this._securityStatus = 1;
        return true;
    }

    const types = this._sock.rQshiftBytes(numTypes);
    Log.Debug("ARD: Server security types: " + Array.from(types));

    // Prefer RSATunnel (33) if offered, else pick first supported
    let chosen = -1;
    if (types.includes(securityTypeRSATunnel)) {
        chosen = securityTypeRSATunnel;
    } else {
        for (const type of types) {
            if (this._isSupportedSecurityType(type)) {
                chosen = type;
                break;
            }
        }
    }

    if (chosen === -1) {
        return this._fail("Unsupported security types (types: " + Array.from(types) + ")");
    }

    this._rfbAuthScheme = chosen;
    this._sock.sQpush8(chosen);
    // Type 33 (RSATunnel) requires the auth byte and first payload
    // in a single TCP segment — defer flush to the RSATunnel handler.
    if (chosen !== securityTypeRSATunnel) {
        this._sock.flush();
    }
    Log.Info("ARD: Selected security type " + chosen);

    this._rfbInitState = 'Authentication';
    return true;
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
    if (this._rfbInitState === 'ArdSessionSelect' && this._rfbAppleARD) {
        return this._ardSessionSelect();
    }
    return _origInitMsg.call(this);
};

// ===== (c) ServerInit — parse Apple extension from name field =====

RFB.prototype._negotiateServerInit = function () {
    if (!this._rfbAppleARD) {
        return _origNegotiateServerInit.call(this);
    }

    // ARD ServerInit: standard 24-byte header + name field
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

    // Detect extended ServerInit by checking byte 0 of the name field
    // for NUL. Only byte 0 matters — byte 1 may be non-zero.
    // This works for ALL auth types including RSATunnel (type 33).
    const nameStr = this._sock.rQshiftStr(nameLength);
    let name;

    if (this._rfbAppleARD && nameLength >= 22 && nameStr.charCodeAt(0) === 0x00) {
        // Extended ServerInit: bytes 0-1 = marker, 2-5 = flags, 6-21 = capability bitmap
        this._ardServerFlags = ((nameStr.charCodeAt(2) << 24) |
                                 (nameStr.charCodeAt(3) << 16) |
                                 (nameStr.charCodeAt(4) << 8)  |
                                  nameStr.charCodeAt(5)) >>> 0;
        this._ardCapabilityBitmap = new Uint8Array(16);
        for (let i = 0; i < 16; i++) {
            this._ardCapabilityBitmap[i] = nameStr.charCodeAt(6 + i);
        }
        this._ardSessionSelectNeeded = !!(this._ardServerFlags & serverFlagSessionSelect);
        name = nameStr.substring(nameStr.lastIndexOf('\x00') + 1);

        Log.Info("ARD: Extended ServerInit — flags=0x" +
                 this._ardServerFlags.toString(16).padStart(8, '0') +
                 ", sessionSelect=" + this._ardSessionSelectNeeded +
                 ", name=" + name);
    } else {
        name = nameStr;
        Log.Info("ARD: Standard ServerInit — nameLength=" + nameLength +
                 (nameLength >= 1 ? ", byte0=0x" + nameStr.charCodeAt(0).toString(16) : ""));
    }

    name = decodeUTF8(name, true);

    Log.Info("ARD: Screen " + width + "x" + height + ", name: " + name);

    this._setDesktopName(name);
    this._resize(width, height);

    if (!this._viewOnly) {
        this._keyboard.grab();
        this._asyncClipboard.grab();
    }

    this._fbDepth = 24;

    // Session Select path: defer everything until session is granted
    if (this._ardSessionSelectNeeded) {
        Log.Info("ARD: Session Select needed — entering ArdSessionSelect state");
        this._rfbInitState = 'ArdSessionSelect';
        this._ardSessionSelectStage = 'readInfo';
        return true;
    }


    // Normal (non-session-select) path — matches ARD init order:
    // ViewerInfo → SetMode → SetDisplay → AutoPasteboard
    // → SetEncodings → PixelFormat → SetEncodings
    // → SetEncryption → FBUpdateRequest
    RFB.messages.ardViewerInfo(this._sock);
    RFB.messages.ardSetMode(this._sock, 1);
    RFB.messages.ardSetDisplay(this._sock);
    RFB.messages.ardAutoPasteboard(this._sock, 1);
    this._sendEncodings();
    RFB.messages.pixelFormat(this._sock, this._fbDepth, true);
    this._sendEncodings();

    // Request session encryption before FBUpdateRequest
    if (this._ardAuthKey && this._ardEncryptionMode === 2) {
        RFB.messages.ardSetEncryption(this._sock, 1);
        Log.Info("ARD: Sent SetEncryption request (cmd=1)");
    } else if (this._ardAuthKey) {
        Log.Info("ARD: Keystroke-only encryption mode — skipping tunnel encryption");
    }

    // CRITICAL: Never send FBUpdateRequest with 0x0 dimensions —
    // causes screensharingd to hang in zlib deflate infinite loop
    if (width > 0 && height > 0) {
        this._ardRequestFullUpdate(width, height);
    } else {
        Log.Warn("ARD: Server reported 0x0 dimensions, deferring FBUpdateRequest");
        this._ardDeferredFBURequest = true;
    }

    this._updateConnectionState('connected');
    ardUpdateInfoPanel(this);
    return true;
};

// ===== (d) Encoding negotiation =====

RFB.prototype._sendEncodings = function () {
    if (!this._rfbAppleARD) {
        return _origSendEncodings.call(this);
    }

    const encs = [];

    // Data encodings — standard only for Layer 1
    encs.push(encodings.encodingCopyRect);
    encs.push(encodings.encodingZlib);
    encs.push(encodings.encodingZRLE);
    encs.push(encodings.encodingHextile);
    encs.push(encodings.encodingRRE);
    encs.push(encodings.encodingRaw);

    // ARD pseudo-encodings
    encs.push(pseudoEncodingArdCursorPos);          // 1100
    encs.push(pseudoEncodingArdDisplayInfo);        // 1101
    encs.push(pseudoEncodingArdUserInfo);           // 1102
    if (this._ardEncryptionMode === 2) {
        encs.push(pseudoEncodingArdSessionEncryption); // 1103
    }
    encs.push(pseudoEncodingArdCursorAlpha);        // 1104
    encs.push(pseudoEncodingArdDisplayInfo2);       // 1105
    encs.push(pseudoEncodingArdDeviceInfo);         // 1107
    encs.push(pseudoEncodingArdKeyboardInput);      // 1109

    // Standard pseudo-encodings
    encs.push(encodings.pseudoEncodingDesktopSize);
    encs.push(encodings.pseudoEncodingLastRect);
    encs.push(encodings.pseudoEncodingCursor);

    RFB.messages.clientEncodings(this._sock, encs);
};

// ===== (e) S→C message dispatch =====

RFB.prototype._normalMsg = function () {
    if (this._rfbAppleARD && this._FBU.rects === 0) {
        // Check for a pending ARD message type from a previous partial read,
        // or peek at the next byte to determine the message type.
        let msgType;
        if (this._ardPendingMsgType !== null) {
            msgType = this._ardPendingMsgType;
        } else {
            if (this._sock.rQwait("msg type", 1)) { return false; }
            msgType = this._sock.rQpeek8();
        }

        let ret;
        switch (msgType) {
            case serverMsgTypeAck:   // 0x04 — zero payload
                this._sock.rQskipBytes(1);
                this._ardPendingMsgType = null;
                Log.Debug("ARD: ServerAck");
                return true;

            case serverMsgTypeNOP:   // 0x07 — zero payload
                this._sock.rQskipBytes(1);
                this._ardPendingMsgType = null;
                return true;

            case serverMsgTypeStateChange:  // 0x14
                if (this._ardPendingMsgType === null) {
                    this._sock.rQshift8(); // consume type byte (first attempt)
                }
                ret = this._ardHandleStateChange();
                this._ardPendingMsgType = ret ? null : msgType;
                return ret;

            case serverMsgTypeClipboard:    // 0x1f
                if (this._ardPendingMsgType === null) {
                    this._sock.rQshift8(); // consume type byte (first attempt)
                }
                ret = this._ardHandleServerClipboard();
                this._ardPendingMsgType = ret ? null : msgType;
                return ret;

            case serverMsgTypeDragEvent:    // 0x20
                if (this._ardPendingMsgType === null) {
                    this._sock.rQshift8(); // consume type byte (first attempt)
                }
                ret = this._ardHandleServerDrag();
                this._ardPendingMsgType = ret ? null : msgType;
                return ret;

            case serverMsgTypeDisplayInfo2: // 0x51
                if (this._ardPendingMsgType === null) {
                    this._sock.rQshift8(); // consume type byte (first attempt)
                }
                ret = this._ardHandleDisplayInfo2Msg();
                this._ardPendingMsgType = ret ? null : msgType;
                return ret;
        }
        // Not an ARD-specific type — fall through to upstream
    }

    const result = _origNormalMsg.call(this);

    // Deferred FBU: when session select completes and server sends a
    // DisplayInfo or DesktopSize with real dimensions, send FBUpdateRequest
    if (this._ardDeferredFBURequest && this._FBU.rects === 0 &&
        this._fbWidth > 0 && this._fbHeight > 0) {
        this._ardDeferredFBURequest = false;
        Log.Info("ARD: Sending deferred FBUpdateRequest (" +
                 this._fbWidth + "x" + this._fbHeight + ")");
        this._ardRequestFullUpdate(this._fbWidth, this._fbHeight);
    }

    // Deferred session encryption activation: once all FBU rects are
    // consumed and we have a pending encryption handshake, acknowledge
    // and enable stream encryption.
    if (this._ardPendingEncryption && this._FBU.rects === 0) {
        const pending = this._ardPendingEncryption;
        this._ardPendingEncryption = null;

        // Send acknowledgement (plaintext — encryption not active yet)
        RFB.messages.ardSetEncryption(this._sock, 2);
        Log.Info("ARD: Sent SetEncryption ack (cmd=2)");

        this._enableStreamEncryption(pending.key, pending.iv);
    }

    // After each completed FBU, re-subscribe to AutoFBUpdate so the
    // server keeps pushing frames. Without this the server's subscription
    // silently expires after a few seconds of C→S silence.
    if (this._rfbAppleARD && this._FBU.rects === 0 &&
        this._fbWidth > 0 && this._fbHeight > 0) {
        RFB.messages.ardAutoFBUpdate(this._sock, 1,
            0, 0, this._fbWidth, this._fbHeight);
    }

    return result;
};

// ===== (f) ARD S→C message handlers (stubs) =====

// StateChange: [type(1)][pad(1)][size(2)][flags(2)][status(2)][extra...]
// Size field is variable — may contain more than 4 bytes of payload
// NOTE: type byte already consumed by _normalMsg dispatcher
RFB.prototype._ardHandleStateChange = function () {
    // Need pad(1) + size(2) = 3 bytes minimum (type already consumed)
    if (this._sock.rQwait("StateChange header", 3)) { return false; }

    const hdr = this._sock.rQpeekBytes(3);
    const size = (hdr[1] << 8) | hdr[2];

    // Wait for full message: pad(1) + size(2) + payload(size)
    if (this._sock.rQwait("StateChange full", 3 + size)) { return false; }

    this._sock.rQskipBytes(3); // pad + size

    if (size < 4) {
        // Malformed — skip whatever payload exists
        if (size > 0) { this._sock.rQskipBytes(size); }
        return true;
    }

    const flags = this._sock.rQshift16();
    const status = this._sock.rQshift16();

    // Skip any extra payload beyond flags+status
    if (size > 4) {
        this._sock.rQskipBytes(size - 4);
    }

    Log.Info("ARD: StateChange — status=" + status + ", flags=0x" + flags.toString(16));

    switch (status) {
        case stateLocalUserClosed:
            Log.Info("ARD: Local user closed session");
            this.disconnect();
            break;

        case statePasteboardChanged:
            // Server pasteboard changed — request clipboard content
            Log.Info("ARD: PasteboardChanged — requesting clipboard");
            RFB.messages.ardClipboardRequest(this._sock,
                0, this._ardClipboardSessionId); // format=0 (pasteboard)
            break;

        case statePasteboardDataNeeded:
            // Server needs our clipboard — send it
            if (this._ardClipboardOutgoing) {
                this._ardSendClipboard(this._ardClipboardOutgoing);
            }
            break;

        case stateTickle:
            // Server stops pushing FBUs after ~3s of C→S silence and
            // sends Tickles waiting for a response. AutoFBUpdate tells
            // it the client is alive and streaming should resume.
            if (this._fbWidth > 0 && this._fbHeight > 0) {
                RFB.messages.ardAutoFBUpdate(this._sock, 1,
                    0, 0, this._fbWidth, this._fbHeight);
            }
            break;

        case stateSleep:
        case stateWake:
            this.dispatchEvent(new CustomEvent("ardstatechange", {
                detail: { status: status, name: status === stateSleep ? 'sleep' : 'wake' }
            }));
            break;

        case stateCursorHidden:
            this._ardCursorVisible = false;
            this._ardSetEmptyCursor();
            break;

        case stateCursorVisible:
            this._ardCursorVisible = true;
            this._ardRestoreCursor();
            break;
    }

    return true;
};

// ServerClipboard: [type(1)][format(1)][reserved(2)][sessionID(4)][uncompSize(4)][compSize(4)][zlib...]
// Payload after zlib decompression is Apple pasteboard format:
// [u32be numTypes][per type: [u32be nameLen][name][u32be flags][u32be numProps][props...][u32be dataLen][data]]
// NOTE: type byte already consumed by _normalMsg dispatcher
RFB.prototype._ardHandleServerClipboard = function () {
    if (this._sock.rQwait("ServerClipboard header", 15)) { return false; }

    const headerBytes = this._sock.rQpeekBytes(15);
    const compressedSize = ((headerBytes[11] << 24) | (headerBytes[12] << 16) |
                            (headerBytes[13] << 8)  |  headerBytes[14]) >>> 0;

    if (this._sock.rQwait("ServerClipboard payload", 15 + compressedSize)) { return false; }

    this._sock.rQskipBytes(1); // format
    this._sock.rQskipBytes(2); // reserved
    const sessionId = this._sock.rQshift32();
    const uncompSize = this._sock.rQshift32();
    this._sock.rQskipBytes(4); // compressed size (already read)

    this._ardClipboardSessionId = sessionId;

    if (compressedSize > 0) {
        const compData = this._sock.rQshiftBytes(compressedSize);
        try {
            const inflator = new Inflator();
            inflator.setInput(compData);
            const decompressed = inflator.inflate(uncompSize);
            const text = ardParsePasteboard(decompressed);
            if (text !== null) {
                Log.Info("ARD: ServerClipboard — " + text.length + " chars");
                this._writeClipboard(text);
            } else {
                Log.Warn("ARD: ServerClipboard — no text type found in pasteboard");
            }
        } catch (e) {
            Log.Warn("ARD: ServerClipboard decompression/parse failed: " + e.message);
        }
    } else {
        this._sock.rQskipBytes(compressedSize);
    }

    return true;
};

// ServerDragEvent: [type(1)][sessionID(4)][extraSize(4)][extra...]
// NOTE: type byte already consumed by _normalMsg dispatcher
RFB.prototype._ardHandleServerDrag = function () {
    if (this._sock.rQwait("ServerDrag header", 8)) { return false; }

    const headerBytes = this._sock.rQpeekBytes(8);
    const extraSize = (headerBytes[4] << 24) | (headerBytes[5] << 16) |
                      (headerBytes[6] << 8)  |  headerBytes[7];

    if (this._sock.rQwait("ServerDrag payload", 8 + extraSize)) { return false; }

    this._sock.rQskipBytes(8 + extraSize);
    Log.Debug("ARD: ServerDragEvent — extraSize=" + extraSize + " (skipped, Layer 2)");
    return true;
};

// DisplayInfo2 message: [type(1)][payloadSize(2)][payload...]
// NOTE: type byte already consumed by _normalMsg dispatcher
RFB.prototype._ardHandleDisplayInfo2Msg = function () {
    if (this._sock.rQwait("DisplayInfo2Msg header", 2)) { return false; }

    const headerBytes = this._sock.rQpeekBytes(2);
    const payloadSize = (headerBytes[0] << 8) | headerBytes[1];

    if (this._sock.rQwait("DisplayInfo2Msg payload", 2 + payloadSize)) { return false; }

    this._sock.rQskipBytes(2 + payloadSize);
    Log.Debug("ARD: DisplayInfo2 message — size=" + payloadSize);
    return true;
};

// ===================================================================
//  Session Select State Machine
// ===================================================================

RFB.prototype._ardSessionSelect = function () {
    switch (this._ardSessionSelectStage) {
        case 'readInfo': {
            // S→C SessionInfo: [u16be bodySize][u16be ver][u32be allowedCmds][u32be reserved][str user]
            if (this._sock.rQwait("SessionInfo header", 2)) { return false; }
            const bsHdr = this._sock.rQpeekBytes(2);
            const bodySize = (bsHdr[0] << 8) | bsHdr[1];
            if (this._sock.rQwait("SessionInfo body", 2 + bodySize)) { return false; }

            this._sock.rQskipBytes(2); // bodySize consumed
            const ver = this._sock.rQshift16();
            const allowedCmds = this._sock.rQshift32();
            this._sock.rQskipBytes(4); // reserved
            // Read NUL-terminated console username
            const userBytesLen = bodySize - 10;
            let user = '';
            if (userBytesLen > 0) {
                const usernameBytes = this._sock.rQshiftBytes(userBytesLen);
                for (let i = 0; i < usernameBytes.length; i++) {
                    if (usernameBytes[i] === 0) break;
                    user += String.fromCharCode(usernameBytes[i]);
                }
            }

            Log.Info("ARD: SessionInfo — ver=0x" + ver.toString(16) +
                     ", allowedCmds=0x" + allowedCmds.toString(16) +
                     ", user=" + user);

            this._ardSessionSelectConsoleUser = user;

            // virtualLogin: 0=always share display, 1=show picker, 2=always virtual
            const vl = this._ardVirtualLogin;

            if (vl === 0 || vl === 2) {
                // Auto-select based on setting
                const cmd = (vl === 2)
                    ? sessionCmdConnectToVirtualDisplay
                    : sessionCmdConnectToConsole;
                this._ardSessionType = cmd;
                RFB.messages.ardSessionCommand(this._sock, cmd, user);
                Log.Info("ARD: SessionSelect — auto-sent command " + cmd +
                         " (virtualLogin=" + vl + ", user=" + user + ")");
                this._ardSessionSelectStage = 'readResult';
            } else if (!user || user.length === 0) {
                // No console user — auto-connect to console
                const cmd = (allowedCmds & (1 << sessionCmdConnectToConsole))
                    ? sessionCmdConnectToConsole
                    : sessionCmdRequestConsole;
                this._ardSessionType = cmd;
                RFB.messages.ardSessionCommand(this._sock, cmd, user);
                Log.Info("ARD: SessionSelect — auto-sent command " + cmd + " (no console user)");
                this._ardSessionSelectStage = 'readResult';
            } else {
                // Console user present — ask the UI which session type to use
                this.dispatchEvent(new CustomEvent('ardsessionselect', {
                    detail: { username: user, allowedCommands: allowedCmds, hasConsoleUser: true }
                }));
                Log.Info("ARD: SessionSelect — dispatched ardsessionselect event for user " + user);
                this._ardSessionSelectStage = 'waitingForUI';
            }
            return true;
        }

        case 'waitingForUI':
            return false; // Blocked — waiting for UI to call selectSessionType()

        case 'readResult': {
            // S→C SessionResult: [u16be bodySize][u16be ver][u32be status][74B reserved]
            if (this._sock.rQwait("SessionResult header", 2)) { return false; }
            const rsHdr = this._sock.rQpeekBytes(2);
            const bodySize = (rsHdr[0] << 8) | rsHdr[1];
            if (this._sock.rQwait("SessionResult body", 2 + bodySize)) { return false; }

            this._sock.rQskipBytes(2); // bodySize
            const ver = this._sock.rQshift16();
            const status = this._sock.rQshift32();
            const remaining = bodySize - 6;
            if (remaining > 0) {
                this._sock.rQskipBytes(remaining);
            }

            Log.Info("ARD: SessionResult — ver=0x" + ver.toString(16) +
                     ", status=" + status);

            if (status === sessionStatusGranted ||
                status === sessionStatusGrantedAfterPending) {
                // Session granted — proceed to post-init
                this._ardPostSessionInit();
                return true;
            } else if (status === sessionStatusPending ||
                       status === sessionStatusPendingAlt) {
                // Pending — loop back to read next result
                Log.Info("ARD: Session pending, waiting for grant...");
                return true;
            } else {
                return this._fail("ARD: Session denied (status=" + status + ")");
            }
        }

        default:
            return this._fail("ARD: Unknown session select stage: " +
                              this._ardSessionSelectStage);
    }
};

// Public API: UI calls this to resume session select after user picks a session type.
// command: 1 = ConnectToConsole (share display), 2 = ConnectToVirtualDisplay
RFB.prototype.selectSessionType = function (command) {
    if (this._ardSessionSelectStage !== 'waitingForUI') {
        Log.Warn("selectSessionType called but not in waitingForUI state");
        return;
    }
    this._ardSessionType = command;
    const user = this._ardSessionSelectConsoleUser || '';
    RFB.messages.ardSessionCommand(this._sock, command, user);
    Log.Info("ARD: SessionSelect — sent command " + command + " for user " + user);
    this._ardSessionSelectStage = 'readResult';
    this._ardSessionSelect(); // Resume protocol handling
};

// Post-session-select initialization: send protocol setup messages,
// then transition to connected WITHOUT sending FBUpdateRequest (0x0 dimensions)
RFB.prototype._ardPostSessionInit = function () {
    Log.Info("ARD: Session granted — sending protocol setup");

    // Same init order as normal path
    RFB.messages.ardViewerInfo(this._sock);
    RFB.messages.ardSetMode(this._sock, 1);
    RFB.messages.ardSetDisplay(this._sock);
    RFB.messages.ardAutoPasteboard(this._sock, 1);
    this._sendEncodings();
    RFB.messages.pixelFormat(this._sock, this._fbDepth, true);
    this._sendEncodings();

    // Request session encryption before FBUpdateRequest
    if (this._ardAuthKey && this._ardEncryptionMode === 2) {
        RFB.messages.ardSetEncryption(this._sock, 1);
        Log.Info("ARD: Sent SetEncryption request (cmd=1)");
    }

    // Defer FBUpdateRequest — dimensions are still 0x0, will send when valid
    this._ardDeferredFBURequest = true;

    this._updateConnectionState('connected');
    ardUpdateInfoPanel(this);
};

// Request a full (non-incremental) framebuffer update and enable
// automatic server-pushed updates. Sends a second pair after 50ms
// to ensure the server starts streaming immediately.
RFB.prototype._ardRequestFullUpdate = function (w, h) {
    RFB.messages.fbUpdateRequest(this._sock, false, 0, 0, w, h);
    RFB.messages.ardAutoFBUpdate(this._sock, 1, 0, 0, w, h);

    const sock = this._sock;
    const self = this;
    setTimeout(() => {
        if (self._rfbConnectionState !== 'connected') return;
        RFB.messages.fbUpdateRequest(sock, false, 0, 0, w, h);
        RFB.messages.ardAutoFBUpdate(sock, 1, 0, 0, w, h);
    }, 50);
};

// ===================================================================
//  Phase 2: FBU Pseudo-Encoding Handlers
// ===================================================================

// DisplayInfo (1101): [u16be w][u16be h][u16be displayCount][u16be flags][28B × count]
RFB.prototype._ardHandleDisplayInfo = function () {
    if (this._sock.rQwait("DisplayInfo header", 8)) { return false; }

    const headerBytes = this._sock.rQpeekBytes(8);
    const width = (headerBytes[0] << 8) | headerBytes[1];
    const height = (headerBytes[2] << 8) | headerBytes[3];
    const displayCount = (headerBytes[4] << 8) | headerBytes[5];
    // headerBytes[6..7] = flags

    const totalSize = 8 + displayCount * 28;
    if (this._sock.rQwait("DisplayInfo full", totalSize)) { return false; }

    this._sock.rQskipBytes(8); // header consumed

    this._ardDisplays = [];
    for (let i = 0; i < displayCount; i++) {
        const id = this._sock.rQshift32();
        const dw = this._sock.rQshift16();
        const dh = this._sock.rQshift16();
        this._sock.rQskipBytes(4);  // magic
        this._sock.rQskipBytes(16); // pixel format
        this._ardDisplays.push({ id, w: dw, h: dh });
    }

    Log.Info("ARD: DisplayInfo — " + width + "x" + height +
             ", " + displayCount + " display(s)");

    this.dispatchEvent(new CustomEvent("arddisplayinfo", {
        detail: { width, height, displays: this._ardDisplays }
    }));

    if (width > 0 && height > 0) {
        this._resize(width, height);
    }

    ardUpdateInfoPanel(this);
    return true;
};

// UserInfo (1102): [u16be nameLen][name bytes][u32be imageSize][u32be imageEnc][imageData]
RFB.prototype._ardHandleUserInfo = function () {
    if (this._sock.rQwait("UserInfo nameLen", 2)) { return false; }
    const nlHdr = this._sock.rQpeekBytes(2);
    const nameLen = (nlHdr[0] << 8) | nlHdr[1];

    if (this._sock.rQwait("UserInfo name+imageHeader", 2 + nameLen + 8)) { return false; }

    // Peek at image size to know full message length
    const offset = 2 + nameLen;
    const peekAll = this._sock.rQpeekBytes(offset + 8);
    const imageSize = (peekAll[offset] << 24) | (peekAll[offset + 1] << 16) |
                      (peekAll[offset + 2] << 8) | peekAll[offset + 3];

    const totalSize = 2 + nameLen + 8 + imageSize;
    if (this._sock.rQwait("UserInfo full", totalSize)) { return false; }

    this._sock.rQskipBytes(2); // nameLen
    const username = nameLen > 0
        ? decodeUTF8(this._sock.rQshiftStr(nameLen), true)
        : '';
    this._sock.rQskipBytes(4); // imageSize
    this._sock.rQskipBytes(4); // imageEnc
    if (imageSize > 0) {
        this._sock.rQskipBytes(imageSize); // skip image data
    }

    this._ardRemoteUser = username;
    Log.Info("ARD: UserInfo — user=" + username);

    this.dispatchEvent(new CustomEvent("arduserinfo", {
        detail: { username }
    }));

    ardUpdateInfoPanel(this);
    return true;
};

// DisplayInfo2 as FBU rect (encoding 1105): size-prefixed payload
RFB.prototype._ardHandleDisplayInfo2Rect = function () {
    if (this._sock.rQwait("DisplayInfo2 rect size", 2)) { return false; }
    const hdr = this._sock.rQpeekBytes(2);
    const payloadSize = (hdr[0] << 8) | hdr[1];
    if (this._sock.rQwait("DisplayInfo2 rect payload", 2 + payloadSize)) { return false; }

    this._sock.rQskipBytes(2 + payloadSize);
    Log.Debug("ARD: DisplayInfo2 rect — size=" + payloadSize);
    return true;
};

// CursorAlpha (1104): [u32be cursorId][u32be dataSize][zlib data if dataSize>0]
RFB.prototype._ardHandleCursorAlpha = function () {
    if (this._sock.rQwait("CursorAlpha header", 8)) { return false; }

    const headerBytes = this._sock.rQpeekBytes(8);
    const cursorId = ((headerBytes[0] << 24) | (headerBytes[1] << 16) |
                      (headerBytes[2] << 8) | headerBytes[3]) >>> 0;
    const dataSize = ((headerBytes[4] << 24) | (headerBytes[5] << 16) |
                      (headerBytes[6] << 8) | headerBytes[7]) >>> 0;

    if (this._sock.rQwait("CursorAlpha full", 8 + dataSize)) { return false; }
    this._sock.rQskipBytes(8); // header consumed

    const w = this._FBU.width;
    const h = this._FBU.height;
    const hotx = this._FBU.x;
    const hoty = this._FBU.y;

    if (cursorId >= 1000 && dataSize > 0) {
        // New cursor: decompress zlib (w*h*4 BGRX + w*h alpha)
        const compData = this._sock.rQshiftBytes(dataSize);
        try {
            const expectedSize = w * h * 5; // 4 BGRX + 1 alpha per pixel
            const inflator = new Inflator();
            inflator.setInput(compData);
            const raw = inflator.inflate(expectedSize);

            // Convert BGRX + separate alpha plane to RGBA
            const rgba = new Uint8Array(w * h * 4);
            const bgrxLen = w * h * 4;
            for (let i = 0; i < w * h; i++) {
                rgba[i * 4]     = raw[i * 4 + 2]; // R from BGRX
                rgba[i * 4 + 1] = raw[i * 4 + 1]; // G
                rgba[i * 4 + 2] = raw[i * 4];     // B
                rgba[i * 4 + 3] = raw[bgrxLen + i]; // A from alpha plane
            }

            this._ardCursorCache.set(cursorId, { rgba, hotx, hoty, w, h });
            this._ardCurrentCursorId = cursorId;

            if (this._ardCursorVisible) {
                this._updateCursor(rgba, hotx, hoty, w, h);
            }

            Log.Debug("ARD: CursorAlpha — new cursor id=" + cursorId +
                      " " + w + "x" + h);
        } catch (e) {
            Log.Warn("ARD: CursorAlpha decompression failed: " + e.message);
        }
    } else if (cursorId >= 1000 && dataSize === 0) {
        // Set cached cursor
        const cached = this._ardCursorCache.get(cursorId);
        if (cached && this._ardCursorVisible) {
            this._updateCursor(cached.rgba, cached.hotx, cached.hoty,
                              cached.w, cached.h);
        }
        this._ardCurrentCursorId = cursorId;
        Log.Debug("ARD: CursorAlpha — set cached cursor id=" + cursorId);
    } else {
        // Predefined cursor (id < 1000)
        if (dataSize > 0) {
            this._sock.rQskipBytes(dataSize);
        }
        this._ardSetPredefinedCursor(cursorId);
        Log.Debug("ARD: CursorAlpha — predefined cursor id=" + cursorId);
    }

    return true;
};

// Map predefined cursor IDs to CSS cursor names
RFB.prototype._ardSetPredefinedCursor = function (id) {
    const cursorMap = {
        0: 'default', 1: 'text', 2: 'crosshair', 3: 'grabbing',
        4: 'grab', 5: 'pointer', 6: 'wait', 7: 'help',
        8: 'not-allowed', 9: 'move', 10: 'ns-resize', 11: 'ew-resize',
    };
    const name = cursorMap[id] || 'default';
    this._canvas.style.cursor = name;
};

// Cursor visibility helpers
RFB.prototype._ardSetEmptyCursor = function () {
    const empty = new Uint8Array(4); // 1x1 transparent
    this._updateCursor(empty, 0, 0, 1, 1);
};

RFB.prototype._ardRestoreCursor = function () {
    if (this._ardCurrentCursorId >= 1000) {
        const cached = this._ardCursorCache.get(this._ardCurrentCursorId);
        if (cached) {
            this._updateCursor(cached.rgba, cached.hotx, cached.hoty,
                              cached.w, cached.h);
            return;
        }
    }
    // No cached cursor to restore — show default
    this._refreshCursor();
};

// DeviceInfo (1107): [u16be msgLen][u16be ver][remaining...]
// msgLen is payload size AFTER the 2-byte length field
RFB.prototype._ardHandleDeviceInfo = function () {
    if (this._sock.rQwait("DeviceInfo header", 4)) { return false; }
    const headerBytes = this._sock.rQpeekBytes(4);
    const msgLen = (headerBytes[0] << 8) | headerBytes[1];

    if (this._sock.rQwait("DeviceInfo full", 2 + msgLen)) { return false; }

    this._sock.rQskipBytes(2); // msgLen field
    const ver = this._sock.rQshift16();
    const remaining = msgLen - 2; // subtract ver (2 bytes) only
    if (remaining > 0) {
        this._sock.rQskipBytes(remaining);
    }

    this._ardDeviceInfo = { version: ver };
    Log.Info("ARD: DeviceInfo — ver=" + ver + ", len=" + msgLen);

    this.dispatchEvent(new CustomEvent("arddeviceinfo", {
        detail: this._ardDeviceInfo
    }));

    ardUpdateInfoPanel(this);
    return true;
};

// KeyboardInput (1109): [u16be msgLen][u16be srcCount][u32be flags][u16be strLen][UTF-8 inputSource]
// msgLen is payload size AFTER the 2-byte length field
RFB.prototype._ardHandleKeyboardInput = function () {
    if (this._sock.rQwait("KeyboardInput header", 4)) { return false; }
    const headerBytes = this._sock.rQpeekBytes(4);
    const msgLen = (headerBytes[0] << 8) | headerBytes[1];

    if (this._sock.rQwait("KeyboardInput full", 2 + msgLen)) { return false; }

    this._sock.rQskipBytes(2); // msgLen field
    const srcCount = this._sock.rQshift16();
    const flags = this._sock.rQshift32();
    const strLen = this._sock.rQshift16();
    const inputSource = strLen > 0
        ? decodeUTF8(this._sock.rQshiftStr(strLen), true)
        : '';

    // Skip any remaining data (consumed counts payload bytes after msgLen field)
    const consumed = 2 + 4 + 2 + strLen;
    const leftover = msgLen - consumed;
    if (leftover > 0) {
        this._sock.rQskipBytes(leftover);
    }

    this._ardKeyboardInput = { srcCount, flags, inputSource };
    Log.Info("ARD: KeyboardInput — sources=" + srcCount +
             ", input=" + inputSource);

    this.dispatchEvent(new CustomEvent("ardkeyboardinput", {
        detail: this._ardKeyboardInput
    }));

    ardUpdateInfoPanel(this);
    return true;
};

// Clipboard send helper — wrap in Apple pasteboard format, compress, and send
RFB.prototype._ardSendClipboard = function (text) {
    const pb = ardBuildPasteboard(text);
    const deflator = new Deflator();
    const compressed = deflator.deflate(pb);
    RFB.messages.ardClipboardSend(this._sock, 0, // format=0 (pasteboard)
        this._ardClipboardSessionId, compressed, pb.length);
    Log.Debug("ARD: Sent clipboard — " + text.length + " chars, " +
              pb.length + " pasteboard bytes, " + compressed.length + " compressed");
};

// Patch clipboardPasteFrom — intercept for ARD
RFB.prototype.clipboardPasteFrom = function (text) {
    if (this._rfbAppleARD) {
        if (this._rfbConnectionState !== 'connected' || this._viewOnly) { return; }
        this._ardClipboardOutgoing = text;
        this._ardSendClipboard(text);
        return;
    }
    return _origClipboardPasteFrom.call(this, text);
};

// ===== (g) FBU pseudo-encoding dispatch =====

RFB.prototype._handleRect = function () {
    if (this._rfbAppleARD) {
        switch (this._FBU.encoding) {
            case pseudoEncodingArdCursorPos:  // 1100
                Log.Debug("ARD: CursorPos — x=" + this._FBU.x + ", y=" + this._FBU.y);
                this._cursor.move(this._FBU.x, this._FBU.y);
                return true;

            case pseudoEncodingArdDisplayInfo:  // 1101
                return this._ardHandleDisplayInfo();

            case pseudoEncodingArdUserInfo:  // 1102
                return this._ardHandleUserInfo();

            case pseudoEncodingArdSessionEncryption:  // 1103
                return this._ardHandleSessionEncryption();

            case pseudoEncodingArdCursorAlpha:  // 1104
                return this._ardHandleCursorAlpha();

            case pseudoEncodingArdDisplayInfo2:  // 1105
                return this._ardHandleDisplayInfo2Rect();

            case pseudoEncodingArdDeviceInfo:  // 1107
                return this._ardHandleDeviceInfo();

            case pseudoEncodingArdKeyboardInput:  // 1109
                return this._ardHandleKeyboardInput();
        }
    }
    return _origHandleRect.call(this);
};

// ===== (h) SecurityResult — skip SecurityReason for ARD =====

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
        this.dispatchEvent(new CustomEvent(
            "securityfailure",
            { detail: { status: status } }));
        return this._fail("ARD authentication failed (status " + status + ")");
    }
};

// ===================================================================
//  LAYER 2a: EncryptedEvent (0x10) — Issue #7
// ===================================================================

// Capture the auth key from Type 30 (DH) authentication.
// We replicate the upstream async handler and save the MD5 digest
// as _ardAuthKey for use by EncryptedEvent and encoding 1103.

RFB.prototype._negotiateARDAuthAsync = async function (keyLength, serverPublicKey, clientKey) {
    const clientPublicKey = legacyCrypto.exportKey("raw", clientKey.publicKey);
    const sharedKey = legacyCrypto.deriveBits(
        { name: "DH", public: serverPublicKey }, clientKey.privateKey, keyLength * 8);

    const username = encodeUTF8(this._rfbCredentials.username).substring(0, 63);
    const password = encodeUTF8(this._rfbCredentials.password).substring(0, 63);

    const credentials = window.crypto.getRandomValues(new Uint8Array(128));
    for (let i = 0; i < username.length; i++) {
        credentials[i] = username.charCodeAt(i);
    }
    credentials[username.length] = 0;
    for (let i = 0; i < password.length; i++) {
        credentials[64 + i] = password.charCodeAt(i);
    }
    credentials[64 + password.length] = 0;

    const key = await legacyCrypto.digest("MD5", sharedKey);

    // Save the auth key for EncryptedEvent and session encryption
    this._ardAuthKey = new Uint8Array(key);
    Log.Info("ARD: Captured auth key from Type 30 DH exchange");

    const cipher = await legacyCrypto.importKey(
        "raw", key, { name: "AES-ECB" }, false, ["encrypt"]);
    const encrypted = await legacyCrypto.encrypt({ name: "AES-ECB" }, cipher, credentials);

    this._rfbCredentials.ardCredentials = encrypted;
    this._rfbCredentials.ardPublicKey = clientPublicKey;

    this._resumeAuthentication();
};

// Lazily create sync ECB cipher from auth key
RFB.prototype._getArdECBCipher = function () {
    if (!this._ardECBCipher && this._ardAuthKey) {
        this._ardECBCipher = new AES128ECB(this._ardAuthKey);
    }
    return this._ardECBCipher;
};

// Build 16-byte encrypted key event payload
// Format: [0xFF, down, keysym(u32be), timestamp(u32be), reserved(2), keycode(2), unicode(2)]
RFB.prototype._buildEncryptedKeyPayload = function (keysym, down) {
    const buf = new Uint8Array(16);
    const dv = new DataView(buf.buffer);
    buf[0] = 0xFF;
    buf[1] = down ? 1 : 0;
    dv.setUint32(2, keysym, false);      // keysym, big-endian
    dv.setUint32(6, (performance.now() * 1000) >>> 0, false);  // timestamp
    // bytes 10-11: reserved (0)
    // bytes 12-13: keycode (0 — no physical keycode in this context)
    // bytes 14-15: unicode (0)
    return buf;
};

// Patch sendKey — intercept for EncryptedEvent when applicable
RFB.prototype.sendKey = function (keysym, code, down) {
    if (this._rfbAppleARD && this._ardAuthKey && !this._ardEncryptionEnabled) {
        if (this._rfbConnectionState !== 'connected' || this._viewOnly) { return; }
        if (down === undefined) {
            this.sendKey(keysym, code, true);
            this.sendKey(keysym, code, false);
            return;
        }
        const cipher = this._getArdECBCipher();
        const payload = this._buildEncryptedKeyPayload(keysym || 0, down);
        const encrypted = cipher.encrypt(payload);
        RFB.messages.encryptedEvent(this._sock, 0, encrypted);
        return;
    }
    return _origSendKey.call(this, keysym, code, down);
};

// ===================================================================
//  LAYER 2b: RSATunnel Auth (Type 33) — Issue #8
// ===================================================================

// Patch _isSupportedSecurityType — add type 33
RFB.prototype._isSupportedSecurityType = function (type) {
    if (type === securityTypeRSATunnel) return true;
    return _origIsSupportedSecurityType.call(this, type);
};

// Patch _negotiateAuthentication — add case 33
RFB.prototype._negotiateAuthentication = function () {
    if (this._rfbAuthScheme === securityTypeRSATunnel) {
        return this._negotiateRSATunnelAuth();
    }
    return _origNegotiateAuthentication.call(this);
};

// RSATunnel state machine
//
// After upstream sends 0x21 (type selection), we send a key request.
// Server responds with its RSA public key. We then encrypt credentials
// and send them back. Server responds with auth result.
//
// Stages: 0=sendKeyReq → 1=readKey → 10=credentials → 99=async
//         → 20=sendBlob → 30=readResult
RFB.prototype._negotiateRSATunnelAuth = function () {
    switch (this._ardRSATunnelStage) {
        case 0: {
            // Send key request immediately — the server is waiting for this
            // after receiving the 0x21 type selection byte.
            // Format: [u32be payloadLen=10][u16le version=1]["RSA1"][u16be sub=0][u16be pad=0]
            this._sock.sQpush32(10);      // payload length (u32be)
            this._sock.sQpush8(1);        // version LE low byte
            this._sock.sQpush8(0);        //            LE high byte
            this._sock.sQpush8(0x52);     // 'R'
            this._sock.sQpush8(0x53);     // 'S'
            this._sock.sQpush8(0x41);     // 'A'
            this._sock.sQpush8(0x31);     // '1'
            this._sock.sQpush16(0);       // sub-protocol 0 = key request (u16be)
            this._sock.sQpush16(0);       // padding (u16be)
            this._sock.flush();

            Log.Info("ARD: RSATunnel — sent key request");
            this._ardRSATunnelStage = 1;
            return false;
        }

        case 1: {
            // Read server's RSA public key response
            if (this._sock.rQwait("RSATunnel key header", 4)) { return false; }

            const hdr = this._sock.rQpeekBytes(4);
            const payloadLen = (hdr[0] << 24) | (hdr[1] << 16) | (hdr[2] << 8) | hdr[3];
            if (this._sock.rQwait("RSATunnel key payload", 4 + payloadLen)) { return false; }

            this._sock.rQskipBytes(4); // consume payloadLen header

            Log.Info("ARD: RSATunnel — server key payload: " + payloadLen + " bytes");

            // Dump first bytes for debugging
            if (payloadLen >= 6) {
                const peek = this._sock.rQpeekBytes(Math.min(payloadLen, 16));
                Log.Debug("ARD: RSATunnel — payload head: " +
                          Array.from(peek).map(b => b.toString(16).padStart(2, '0')).join(' '));
            }

            const version = this._sock.rQshift8() | (this._sock.rQshift8() << 8); // u16le
            const respType = this._sock.rQshift8() | (this._sock.rQshift8() << 8); // u16le
            const keyDataLen = this._sock.rQshift16(); // u16be

            Log.Info("ARD: RSATunnel — key response: ver=" + version +
                     ", type=" + respType + ", keyLen=" + keyDataLen);

            const keyData = this._sock.rQshiftBytes(keyDataLen);
            // Skip trailing NUL or any remaining bytes
            const remaining = payloadLen - 6 - keyDataLen;
            if (remaining > 0) {
                this._sock.rQskipBytes(remaining);
            }

            // Parse PKCS#1 DER public key
            try {
                this._ardRSATunnelKey = parsePKCS1PublicKey(keyData);
                this._ardCacheRSAKey(keyData);
                Log.Info("ARD: RSATunnel — parsed server RSA key (" +
                         this._ardRSATunnelKey.n.length * 8 + "-bit)");
            } catch (e) {
                return this._fail("ARD: RSATunnel — failed to parse server key: " + e.message);
            }

            // Now check credentials — prompt if needed
            this._ardRSATunnelStage = 10;
            return this._negotiateRSATunnelAuth();
        }

        case 10: {
            // Key already parsed — now get credentials
            if (this._rfbCredentials.username === undefined ||
                this._rfbCredentials.password === undefined) {
                this.dispatchEvent(new CustomEvent(
                    "credentialsrequired",
                    { detail: { types: ["username", "password"] } }));
                return false;
            }

            // Start async credential encryption
            this._ardRSATunnelStage = 99; // waiting for async
            this._negotiateRSATunnelAuthAsync(this._ardRSATunnelKey);
            return false;
        }

        case 20: {
            // Async done — send credential blob
            // [u32be blobSize][u16le 1]["RSA1"][u16be 1][AES creds 128][u16le rsaLen][RSA ct]
            const rsaCt = this._ardRSATunnelRSACt;
            const creds = this._ardRSATunnelCreds;
            const blobSize = 2 + 4 + 2 + 128 + 2 + rsaCt.length;

            this._sock.sQpush32(blobSize);
            this._sock.sQpush8(1);        // version (u16le=1) low byte
            this._sock.sQpush8(0);        //                   high byte
            this._sock.sQpush8(0x52);     // 'R'
            this._sock.sQpush8(0x53);     // 'S'
            this._sock.sQpush8(0x41);     // 'A'
            this._sock.sQpush8(0x31);     // '1'
            this._sock.sQpush16(1);       // sub-protocol 1 (u16be)
            this._sock.sQpushBytes(creds);
            // rsaLen as u16le
            this._sock.sQpush8(rsaCt.length & 0xFF);
            this._sock.sQpush8((rsaCt.length >> 8) & 0xFF);
            this._sock.sQpushBytes(rsaCt);
            this._sock.flush();

            Log.Info("ARD: RSATunnel — sent credential blob (" +
                     blobSize + " bytes, RSA ct=" + rsaCt.length + ")");

            this._ardRSATunnelCreds = null;
            this._ardRSATunnelRSACt = null;
            this._ardRSATunnelStage = 30;
            return false;
        }

        case 30: {
            // Read server response — peek at payloadLen first
            if (this._sock.rQwait("RSATunnel response", 4)) { return false; }

            const rhdr = this._sock.rQpeekBytes(4);
            const payloadLen = (rhdr[0] << 24) | (rhdr[1] << 16) | (rhdr[2] << 8) | rhdr[3];
            if (this._sock.rQwait("RSATunnel response payload", 4 + payloadLen)) { return false; }

            this._sock.rQskipBytes(4); // consume payloadLen header
            if (payloadLen > 0) {
                this._sock.rQskipBytes(payloadLen);
            }

            Log.Info("ARD: RSATunnel — auth response received (payloadLen=" + payloadLen + ")");
            this._rfbInitState = "SecurityResult";
            return true;
        }

        default:
            return false; // Waiting for async (stage 99)
    }
};

// Async part of RSATunnel: generate key, encrypt credentials, encrypt key
RFB.prototype._negotiateRSATunnelAuthAsync = async function (serverKey) {
    try {
        // Generate 16 random bytes as AES key (raw, NOT MD5)
        const aesKey = window.crypto.getRandomValues(new Uint8Array(16));
        this._ardAuthKey = aesKey;
        Log.Info("ARD: RSATunnel — generated 16-byte AES key");

        // Pack credentials (128 bytes: user[64] + pass[64])
        const username = encodeUTF8(this._rfbCredentials.username).substring(0, 63);
        const password = encodeUTF8(this._rfbCredentials.password).substring(0, 63);

        const credentials = window.crypto.getRandomValues(new Uint8Array(128));
        for (let i = 0; i < username.length; i++) {
            credentials[i] = username.charCodeAt(i);
        }
        credentials[username.length] = 0;
        for (let i = 0; i < password.length; i++) {
            credentials[64 + i] = password.charCodeAt(i);
        }
        credentials[64 + password.length] = 0;

        // AES-ECB encrypt credentials with the random key
        const ecb = new AES128ECB(aesKey);
        const encryptedCreds = ecb.encrypt(credentials);
        this._ardRSATunnelCreds = encryptedCreds;

        // RSA-PKCS1v1.5 encrypt the AES key with server's public key
        // Pad e to match n length for RSACipher.importKey
        const keyBytes = serverKey.n.length;
        const ePadded = new Uint8Array(keyBytes);
        ePadded.set(serverKey.e, keyBytes - serverKey.e.length);

        const rsaCipher = await RSACipher.importKey(
            { n: serverKey.n, e: ePadded },
            { name: "RSA-PKCS1-v1_5" }, false, ["encrypt"]);
        const rsaCt = await rsaCipher.encrypt({}, aesKey);
        this._ardRSATunnelRSACt = new Uint8Array(rsaCt);

        Log.Info("ARD: RSATunnel — credentials encrypted, RSA ct=" + rsaCt.length + " bytes");

        this._ardRSATunnelStage = 20;
        this._resumeAuthentication();
    } catch (e) {
        this._fail("ARD: RSATunnel async error: " + e.message);
    }
};

// RSA key caching helpers
RFB.prototype._ardGetCachedRSAKey = function () {
    try {
        const url = this._rfbCredentials._ardKeyUrl || this._url || '';
        const raw = localStorage.getItem('ardRSAKey_' + url);
        if (!raw) return null;
        const obj = JSON.parse(raw);
        const der = new Uint8Array(obj.der);
        return parsePKCS1PublicKey(der);
    } catch (e) {
        return null;
    }
};

RFB.prototype._ardCacheRSAKey = function (derBytes) {
    try {
        const url = this._rfbCredentials._ardKeyUrl || this._url || '';
        localStorage.setItem('ardRSAKey_' + url,
            JSON.stringify({ der: Array.from(derBytes) }));
    } catch (e) {
        Log.Warn("ARD: Failed to cache RSA key: " + e.message);
    }
};

// ===================================================================
//  LAYER 2c: Session Encryption (Encoding 1103) — Issue #6
// ===================================================================

// Handle encoding 1103 in FBU rect
// Payload: [cmd/version(u32)][encKey(16)][encIV(16)] = 36 bytes
RFB.prototype._ardHandleSessionEncryption = function () {
    if (this._sock.rQwait("session encryption", 36)) { return false; }

    const cmdVersion = this._sock.rQshift32();
    const encKeyRaw = this._sock.rQshiftBytes(16);
    const encIVRaw = this._sock.rQshiftBytes(16);

    if (cmdVersion !== 1) {
        Log.Warn("ARD: SessionEncryption — unexpected cmd/version " + cmdVersion);
        return true;
    }

    // Decrypt key and IV using ECB cipher (auth key)
    const cipher = this._getArdECBCipher();
    if (!cipher) {
        Log.Warn("ARD: SessionEncryption — no auth key available, ignoring");
        return true;
    }

    const sessionKey = cipher.decrypt(new Uint8Array(encKeyRaw));
    const sessionIV = cipher.decrypt(new Uint8Array(encIVRaw));

    Log.Info("ARD: SessionEncryption — received key+IV, deferring activation");

    // Defer activation until FBU completion
    this._ardPendingEncryption = {
        key: sessionKey,
        iv: sessionIV
    };

    return true;
};

// Enable stream encryption on the Websock
RFB.prototype._enableStreamEncryption = function (sessionKey, sessionIV) {
    const cbc = new AES128CBC(sessionKey);
    this._sock.enableEncryption(cbc, SHA1, sessionIV);
    this._ardEncryptionEnabled = true;
    this._ardSessionKey = sessionKey;
    this._ardSessionIV = sessionIV;
    Log.Info("ARD: Stream encryption enabled (AES-128-CBC)");

    ardUpdateInfoPanel(this);

    this.dispatchEvent(new CustomEvent("ardencryptionstate",
        { detail: { state: 'full' } }));

    // Any data remaining in the receive queue is now encrypted
    this._sock.reprocessRemainingAsEncrypted();
};

// ===== Websock prototype patches for encrypted transport =====

Websock.prototype.enableEncryption = function (cbcCipher, sha1Fn, iv) {
    this._encCipher = cbcCipher;
    this._encSHA1 = sha1Fn;
    this._encSendIV = new Uint8Array(iv);
    this._encRecvIV = new Uint8Array(iv);
    this._encSendSeq = 0;
    this._encRecvSeq = 0;
    this._encRecvBuf = new Uint8Array(0); // Accumulation buffer for incoming
    Log.Info("ARD: Websock encryption initialized");
};

Websock.prototype.reprocessRemainingAsEncrypted = function () {
    // Extract any unprocessed data from the receive queue
    const remaining = this._rQlen - this._rQi;
    if (remaining <= 0) return;

    const data = new Uint8Array(this._rQ.buffer, this._rQi, remaining);
    const copy = new Uint8Array(data); // Copy before resetting

    // Reset receive queue
    this._rQi = 0;
    this._rQlen = 0;

    // Feed through encrypted receive path
    Log.Info("ARD: Reprocessing " + copy.length + " bytes as encrypted");
    this._encryptedRecv(copy);
};

Websock.prototype._encryptedFlush = function () {
    if (this._sQlen === 0) return;

    const vncData = new Uint8Array(this._sQ.buffer, 0, this._sQlen);
    const L = vncData.length;
    // totalSize must be multiple of 16 and fit: 2 (len) + L (data) + 20 (SHA-1)
    const totalSize = Math.ceil((2 + L + 20) / 16) * 16;

    // Build cleartext: [u16be(L)][vncData][padding][SHA-1(20)]
    const cleartext = new Uint8Array(totalSize);
    const dv = new DataView(cleartext.buffer);
    dv.setUint16(0, L, false);
    cleartext.set(vncData, 2);
    // padding bytes are already zero

    // SHA-1 input: u32be(sendSeq) || cleartext[0..totalSize-21]
    const hashLen = 4 + totalSize - 20;
    const hashInput = new Uint8Array(hashLen);
    const hidv = new DataView(hashInput.buffer);
    hidv.setUint32(0, this._encSendSeq, false);
    hashInput.set(cleartext.subarray(0, totalSize - 20), 4);
    const hash = this._encSHA1(hashInput);
    cleartext.set(hash, totalSize - 20);

    // Encrypt with AES-CBC
    const result = this._encCipher.encrypt(cleartext, this._encSendIV);
    this._encSendIV = new Uint8Array(result.iv); // Update IV to last ciphertext block

    // Wire: [u16be(totalSize)][encrypted]
    const wire = new Uint8Array(2 + totalSize);
    const wdv = new DataView(wire.buffer);
    wdv.setUint16(0, totalSize, false);
    wire.set(result.data, 2);

    this._sQlen = 0;
    this._encSendSeq++;

    if (this.readyState === 'open') {
        this._websocket.send(wire);
    }
};

Websock.prototype._encryptedRecv = function (incoming) {
    // Append incoming to accumulation buffer
    const newBuf = new Uint8Array(this._encRecvBuf.length + incoming.length);
    newBuf.set(this._encRecvBuf);
    newBuf.set(incoming, this._encRecvBuf.length);
    this._encRecvBuf = newBuf;

    let processed = false;
    while (this._encRecvBuf.length >= 2) {
        // Stop processing if the connection has been torn down
        if (this.readyState !== 'open') {
            Log.Warn("ARD: _encryptedRecv stopping — socket no longer open");
            this._encRecvBuf = new Uint8Array(0);
            return;
        }

        // Read ciphertext length
        const ctLen = (this._encRecvBuf[0] << 8) | this._encRecvBuf[1];
        if (ctLen === 0 || ctLen % 16 !== 0) {
            Log.Error("ARD: Invalid encrypted packet length: " + ctLen);
            this._encRecvBuf = new Uint8Array(0);
            return;
        }

        if (this._encRecvBuf.length < 2 + ctLen) {
            break; // Wait for more data
        }

        // Extract and decrypt
        const ct = this._encRecvBuf.slice(2, 2 + ctLen);
        this._encRecvBuf = this._encRecvBuf.slice(2 + ctLen);

        const result = this._encCipher.decrypt(ct, this._encRecvIV);
        this._encRecvIV = new Uint8Array(ct.slice(ct.length - 16)); // Last ciphertext block
        const plaintext = result.data;

        // Extract payload: [u16be(payloadLen)][vncData][padding][SHA-1(20)]
        const pldv = new DataView(plaintext.buffer, plaintext.byteOffset, plaintext.byteLength);
        const payloadLen = pldv.getUint16(0, false);

        // Verify SHA-1
        const hashLen = 4 + plaintext.length - 20;
        const hashInput = new Uint8Array(hashLen);
        const hidv = new DataView(hashInput.buffer);
        hidv.setUint32(0, this._encRecvSeq, false);
        hashInput.set(plaintext.subarray(0, plaintext.length - 20), 4);
        const expected = this._encSHA1(hashInput);
        const actual = plaintext.subarray(plaintext.length - 20);

        let hashOk = true;
        for (let i = 0; i < 20; i++) {
            if (expected[i] !== actual[i]) { hashOk = false; break; }
        }
        if (!hashOk) {
            Log.Error("ARD: Encrypted packet SHA-1 mismatch (seq=" + this._encRecvSeq +
                      "), discarding corrupted data");
            this._encRecvSeq++;
            continue; // Skip corrupted packet, don't push to rQ
        }

        this._encRecvSeq++;

        // Append decrypted VNC data to receive queue
        const vncData = plaintext.subarray(2, 2 + payloadLen);
        if (vncData.length > 0) {
            // Debug: log first byte (VNC message type) of each decrypted packet
            Log.Debug("ARD enc-recv: seq=" + (this._encRecvSeq - 1) +
                      " len=" + vncData.length +
                      " type=0x" + vncData[0].toString(16) +
                      (vncData.length > 1 ? " [" + Array.from(vncData.subarray(0, Math.min(8, vncData.length))).map(b => b.toString(16).padStart(2, '0')).join(' ') + "]" : ""));
            if (this._rQlen === this._rQi) {
                this._rQlen = 0;
                this._rQi = 0;
            }
            if (vncData.length > this._rQbufferSize - this._rQlen) {
                this._expandCompactRQ(vncData.length);
            }
            this._rQ.set(vncData, this._rQlen);
            this._rQlen += vncData.length;
            processed = true;
        }
    }

    if (processed && this._rQlen - this._rQi > 0) {
        this._eventHandlers.message();
    }
};

// Patch Websock.flush for encrypted mode
Websock.prototype.flush = function () {
    if (this._encCipher) {
        return this._encryptedFlush();
    }
    return _origWsFlush.call(this);
};

// Patch Websock._recvMessage for encrypted mode
Websock.prototype._recvMessage = function (e) {
    if (this._encCipher) {
        const u8 = new Uint8Array(e.data);
        this._encryptedRecv(u8);
        return;
    }
    return _origWsRecvMessage.call(this, e);
};

// ===================================================================
//  Static Messages
// ===================================================================

// EncryptedEvent (0x10): [type(1)][flags(1)][encrypted(16)]
RFB.messages.encryptedEvent = function (sock, flags, encrypted) {
    sock.sQpush8(msgTypeEncryptedEvent);
    sock.sQpush8(flags);
    sock.sQpushBytes(encrypted);
    sock.flush();
};

// SetEncryption (0x12): [type(1)][pad(1)][cmd(2)][level(2)][methodCount(2)][methods...]
RFB.messages.ardSetEncryption = function (sock, cmd) {
    sock.sQpush8(msgTypeSetEncryption);
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
};

// SessionCommand: [u16be 72][u16be ver=1][pad4][u8 cmd][pad1][char[64] user] = 74 bytes
RFB.messages.ardSessionCommand = function (sock, cmd, username) {
    sock.sQpush16(72);    // bodySize
    sock.sQpush16(1);     // version
    sock.sQpush32(0);     // padding
    sock.sQpush8(cmd);    // command
    sock.sQpush8(0);      // padding

    // 64-byte NUL-padded username
    const userBuf = new Uint8Array(64);
    const encoded = new TextEncoder().encode(username || '');
    userBuf.set(encoded.subarray(0, Math.min(encoded.length, 63)));
    sock.sQpushBytes(userBuf);
    sock.flush();
};

// ViewerInfo (0x21): [type(1)][pad(1)][u16be 62][u16be appClass=1][u32be appId]
//                    [12B appVer (3×u32be)][12B osVer (3×u32be)][32B cmdBitmap] = 66 bytes
RFB.messages.ardViewerInfo = function (sock) {
    sock.sQpush8(msgTypeViewerInfo);  // 0x21
    sock.sQpush8(0);                  // padding
    sock.sQpush16(62);               // body size

    sock.sQpush16(1);                // appClass (1 = generic viewer)
    sock.sQpush32(0x00000002);       // appId = 2 (Screen Sharing)

    // 12-byte appVersion: 3 × u32be (major, minor, patch)
    sock.sQpush32(6);                // major
    sock.sQpush32(1);                // minor
    sock.sQpush32(0);                // patch

    // 12-byte osVersion: 3 × u32be (major, minor, patch)
    sock.sQpush32(15);               // major (macOS 15)
    sock.sQpush32(0);                // minor
    sock.sQpush32(0);                // patch

    // 32-byte command support bitmap
    const bitmap = new Uint8Array(32);
    bitmap[0]  = 0xb0;
    bitmap[2]  = 0x0c;
    bitmap[3]  = 0x03;
    bitmap[4]  = 0x90;
    bitmap[10] = 0x40;
    sock.sQpushBytes(bitmap);
    sock.flush();

    Log.Info("ARD: Sent ViewerInfo (66 bytes)");
};

// SetMode (0x0a): [type(1)][pad(2)][u8 mode] = 4 bytes
RFB.messages.ardSetMode = function (sock, mode) {
    sock.sQpush8(msgTypeSetMode);  // 0x0a
    sock.sQpush8(0);               // padding
    sock.sQpush8(0);               // padding
    sock.sQpush8(mode);            // mode: 0=observe, 1=control, 2=exclusive
    sock.flush();

    Log.Info("ARD: Sent SetMode (mode=" + mode + ")");
};

// SetDisplay (0x0d): [type(1)][u8 combineAll][pad(2)][u32be displayId] = 8 bytes
RFB.messages.ardSetDisplay = function (sock) {
    sock.sQpush8(msgTypeSetDisplay);  // 0x0d
    sock.sQpush8(1);                  // combineAll = 1 (show all displays)
    sock.sQpush16(0);                 // padding
    sock.sQpush32(0);                 // displayId = 0 (all)
    sock.flush();

    Log.Info("ARD: Sent SetDisplay (combineAll=1)");
};

// AutoFBUpdate (0x09): [type(1)][pad(1)][u16be enabled][u32be interval]
//                      [u16be x][u16be y][u16be w][u16be h] = 16 bytes
// Tells the server to automatically push framebuffer updates
// without waiting for explicit FBUpdateRequests.
RFB.messages.ardAutoFBUpdate = function (sock, enabled, x, y, w, h) {
    sock.sQpush8(msgTypeAutoFBUpdate);  // 0x09
    sock.sQpush8(0);                    // padding
    sock.sQpush16(enabled);             // 1=enable, 0=disable
    sock.sQpush32(0);                   // interval ms (0 = server default)
    sock.sQpush16(x);                   // region x
    sock.sQpush16(y);                   // region y
    sock.sQpush16(w);                   // region width
    sock.sQpush16(h);                   // region height
    sock.flush();
};

// AutoPasteboard (0x15): [type(1)][pad(1)][u16be cmd][pad(4)] = 8 bytes
RFB.messages.ardAutoPasteboard = function (sock, cmd) {
    sock.sQpush8(msgTypeAutoPasteboard);  // 0x15
    sock.sQpush8(0);                      // padding
    sock.sQpush16(cmd);                   // 1=enable, 0=disable
    sock.sQpush32(0);                     // padding
    sock.flush();

    Log.Info("ARD: Sent AutoPasteboard (cmd=" + cmd + ")");
};

// ClipboardRequest (0x0b): [type(1)][u8 format][pad(2)][u32be sessionId] = 8 bytes
RFB.messages.ardClipboardRequest = function (sock, format, sessionId) {
    sock.sQpush8(msgTypeClipboardReq);  // 0x0b
    sock.sQpush8(format);
    sock.sQpush16(0);                   // padding
    sock.sQpush32(sessionId);
    sock.flush();
};

// ClipboardSend (0x1f): [type(1)][u8 format][pad(2)][u32be sessionId]
//                       [u32be uncompSize][u32be compSize][zlibData]
RFB.messages.ardClipboardSend = function (sock, format, sessionId, zlibData, uncompSize) {
    sock.sQpush8(msgTypeClipboardSend);  // 0x1f
    sock.sQpush8(format);
    sock.sQpush16(0);                    // padding
    sock.sQpush32(sessionId);
    sock.sQpush32(uncompSize);
    sock.sQpush32(zlibData.length);
    sock.sQpushBytes(zlibData);
    sock.flush();
};

// ===================================================================
//  Apple Pasteboard Format Helpers
// ===================================================================

// Parse Apple pasteboard binary format, return first text string or null
// Format: [u32be numTypes][per type: [u32be nameLen][name][u32be flags]
//         [u32be numProps][per prop: [u32be keyLen][key][u32be valLen][val]]
//         [u32be dataLen][data]]
function ardParsePasteboard(data) {
    const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const td = new TextDecoder('utf-8');
    let offset = 0;

    if (data.length < 4) return null;
    const numTypes = dv.getUint32(offset); offset += 4;

    for (let t = 0; t < numTypes; t++) {
        if (offset + 4 > data.length) break;
        const nameLen = dv.getUint32(offset); offset += 4;
        if (offset + nameLen > data.length) break;
        const typeName = td.decode(data.subarray(offset, offset + nameLen));
        offset += nameLen;

        if (offset + 4 > data.length) break;
        const flags = dv.getUint32(offset); offset += 4;

        if (offset + 4 > data.length) break;
        const numProps = dv.getUint32(offset); offset += 4;
        for (let p = 0; p < numProps; p++) {
            if (offset + 4 > data.length) break;
            const keyLen = dv.getUint32(offset); offset += 4;
            offset += keyLen; // skip key
            if (offset + 4 > data.length) break;
            const valLen = dv.getUint32(offset); offset += 4;
            offset += valLen; // skip value
        }

        if (offset + 4 > data.length) break;
        const dataLen = dv.getUint32(offset); offset += 4;
        if (offset + dataLen > data.length) break;

        if (typeName === 'public.utf8-plain-text') {
            return td.decode(data.subarray(offset, offset + dataLen));
        }
        offset += dataLen;
    }
    return null;
}

// Build Apple pasteboard binary format from text string
function ardBuildPasteboard(text) {
    const te = new TextEncoder();
    const typeName = te.encode('public.utf8-plain-text');
    const textData = te.encode(text);

    // Layout: [u32 numTypes=1][u32 nameLen][name][u32 flags=0][u32 numProps=0][u32 dataLen][data]
    const size = 4 + 4 + typeName.length + 4 + 4 + 4 + textData.length;
    const buf = new Uint8Array(size);
    const dv = new DataView(buf.buffer);
    let offset = 0;

    dv.setUint32(offset, 1); offset += 4;                  // numTypes
    dv.setUint32(offset, typeName.length); offset += 4;     // nameLen
    buf.set(typeName, offset); offset += typeName.length;   // typeName
    dv.setUint32(offset, 0); offset += 4;                  // flags
    dv.setUint32(offset, 0); offset += 4;                  // numProps
    dv.setUint32(offset, textData.length); offset += 4;     // dataLen
    buf.set(textData, offset);                              // data

    return buf;
}

// ===================================================================
//  Connection Info Panel
// ===================================================================

function ardUpdateInfoPanel(rfb) {
    const el = (id) => document.getElementById(id);
    const panel = el('ard_info_panel');
    if (!panel) return;

    const set = (id, val) => {
        const e = el(id);
        if (e) e.textContent = val || '—';
    };

    set('ard_info_server', rfb._fbName || '');
    set('ard_info_resolution', rfb._fbWidth && rfb._fbHeight
        ? rfb._fbWidth + ' x ' + rfb._fbHeight : '—');
    set('ard_info_displays', rfb._ardDisplays.length > 0
        ? rfb._ardDisplays.map(d => d.w + 'x' + d.h).join(', ') : '—');
    set('ard_info_encryption', rfb._ardEncryptionEnabled
        ? 'AES-128-CBC' : (rfb._ardAuthKey ? 'Keystroke only' : 'None'));
    set('ard_info_mode', rfb._viewOnly ? 'Observe' : 'Control');
    const sessionLabels = { 0: 'Request Console', 1: 'Share Display', 2: 'Virtual Display' };
    set('ard_info_session', rfb._ardSessionType !== null
        ? sessionLabels[rfb._ardSessionType] || 'Unknown (' + rfb._ardSessionType + ')'
        : '—');
    set('ard_info_user', rfb._ardRemoteUser || '—');
    set('ard_info_keyboard', rfb._ardKeyboardInput
        ? rfb._ardKeyboardInput.inputSource : '—');
    set('ard_info_protocol', rfb._rfbAppleARD ? 'ARD (003.889)' : 'Standard VNC');
}

Log.Info("ARD: Protocol patch applied to RFB.prototype (Layer 1 + Layer 2b)");
