# noVNC-ARD

Apple Remote Desktop (ARD) protocol extensions for [noVNC](https://github.com/novnc/noVNC).

Upstream noVNC lives as an untouched git submodule at `noVNC/`. All ARD-specific code lives in `ard/`. The submodule is never modified.

## Structure

```
noVNC-ARD/
  noVNC/                  ← git submodule (upstream, untouched)
  ard/
    ard-constants.js      ← encoding IDs, message types, status codes
    ard-patch.js          ← monkey-patches RFB prototype for ARD support
    decoders/             ← ARD-specific pixel decoders (Layer 2+)
  ard.html                ← entry point (loads noVNC + ARD patch)
  ard.css                 ← ARD-specific styles (Layer 2+)
```

## Usage

```bash
# Clone with submodule
git clone --recurse-submodules https://github.com/peetinc/noVNC-ARD.git

# Proxy a macOS Screen Sharing server through websockify
websockify --web . 6088 <host>:5900

# Open in browser
open http://localhost:6088/ard.html
```

## How It Works

`ard-patch.js` is imported before the noVNC UI and patches `RFB.prototype` to:

- Detect ARD servers (`003.889` version string)
- Send Apple-extended ClientInit (`0xC1`)
- Parse Extended ServerInit (flags, capabilities, machine name)
- Handle ARD-specific S→C messages (StateChange, ServerClipboard, etc.)
- Negotiate ARD encoding lists
- Guard against 0×0 dimension FBUpdateRequests

Standard VNC connections pass through unmodified.

## Status

**Layer 1 (Protocol Scaffolding)** — complete. Connects to macOS Screen Sharing servers using standard encodings (Zlib, ZRLE, Hextile, Raw) via Type 30 (DH) auth.

See [milestones](https://github.com/peetinc/noVNC-ARD/milestones) for the roadmap.
