/*
 * noVNC-ARD: ARD Protocol Constants
 *
 * All encoding IDs, message types, and status codes for
 * Apple Remote Desktop VNC extensions (version 003.889).
 */

// ===== Data Encodings =====
// These produce pixel data in FBU rects

export const encodingArdHalftone   = 1000;
export const encodingArdGray16     = 1001;
export const encodingArdThousands  = 1002;
export const encodingArdMVS        = 1011;

// ===== Capability Signal =====
// Not a pixel encoding; signals ProMode (High Performance) support

export const encodingArdProMode    = 1010;

// ===== Pseudo-Encodings =====
// These carry metadata in FBU rects, not pixel data

export const pseudoEncodingArdCursorPos       = 1100;
export const pseudoEncodingArdDisplayInfo      = 1101;
export const pseudoEncodingArdUserInfo         = 1102;
export const pseudoEncodingArdSessionEncryption = 1103;
export const pseudoEncodingArdCursorAlpha      = 1104;
export const pseudoEncodingArdDisplayInfo2     = 1105;
export const pseudoEncodingArdTouch            = 1106;
export const pseudoEncodingArdDeviceInfo       = 1107;
export const pseudoEncodingArdKeyboardInput    = 1109;
export const pseudoEncodingArdMediaStream      = 1110;

// ===== C→S Message Types =====

export const msgTypeNOP               = 0x07;
export const msgTypeSetServerScaling  = 0x08;
export const msgTypeAutoFBUpdate      = 0x09;
export const msgTypeSetMode           = 0x0a;
export const msgTypeClipboardReq      = 0x0b;
export const msgTypeSessionVisibility = 0x0c;
export const msgTypeSetDisplay        = 0x0d;
export const msgTypeDragEvent         = 0x0e;
export const msgTypeEncryptedEvent    = 0x10;
export const msgTypeSetEncryption     = 0x12;
export const msgTypeSessionVisibility2 = 0x14;
export const msgTypeAutoPasteboard    = 0x15;
export const msgTypeGestureEvent      = 0x17;
export const msgTypeClipboardSend     = 0x1f;
export const msgTypeViewerInfo        = 0x21;

// ===== S→C Message Types =====

export const serverMsgTypeAck         = 0x04;
export const serverMsgTypeNOP         = 0x07;
export const serverMsgTypeStateChange = 0x14;
export const serverMsgTypeClipboard   = 0x1f;
export const serverMsgTypeDragEvent   = 0x20;
export const serverMsgTypeDisplayInfo2 = 0x51;

// ===== StateChange Status Codes =====

export const stateLocalUserClosed     = 1;
export const statePasteboardChanged   = 2;
export const statePasteboardDataNeeded = 3;
export const stateTickle              = 4;
export const stateSleep               = 5;
export const stateWake                = 6;
export const stateCursorHidden        = 11;
export const stateCursorVisible       = 12;

// ===== ClientInit Flags =====

export const clientInitShared   = 0x01;
export const clientInitSelect   = 0x40;
export const clientInitEnhanced = 0x80;
export const clientInitARD      = 0xC1; // Shared + Select + Enhanced

// ===== ServerInit Flags (bit positions) =====

export const serverFlagObserve         = 0x01;
export const serverFlagMayControl      = 0x02;
export const serverFlagSessionSelect   = 0x04;
export const serverFlagNoVirtualDisplay = 0x08;

// ===== Security Types =====

export const securityTypeARD          = 30;
export const securityTypeRSATunnel    = 33;
