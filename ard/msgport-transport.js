// MessagePort transport for noVNC — lets the parent page own the byte pipe.
//
// When ard.html is loaded with ?path=msgport (via the standard `path` URL
// param resolving to the literal URI "msgport:"), Websock.open() waits for the
// parent window to deliver a MessagePort via postMessage:
//
//     iframe.contentWindow.postMessage({ type: 'lb-vnc-port' }, '*', [port]);
//
// and attaches a WebSocket-shaped adapter around it. The parent bridges the
// port to whatever transport it owns (WebRTC DataChannel mux stream, local-RA
// forward, ...). Wire protocol on the port:
//     parent → here:  ArrayBuffer            (bytes from the VNC server)
//     parent → here:  {type:'close', reason} (transport died)
//     here  → parent: ArrayBuffer            (bytes for the VNC server)
//     here  → parent: {type:'close'}         (RFB closed)
//
// The adapter satisfies Websock.attach()'s rawChannelProps contract:
// send, close, binaryType, onerror, onmessage, onopen, protocol, readyState.

import Websock from '../noVNC/core/websock.js';
import * as Log from '../noVNC/core/util/logging.js';

let pendingPort = null;
let portWaiter = null;

window.addEventListener('message', (ev) => {
    if (!ev.data || ev.data.type !== 'lb-vnc-port') return;
    const port = ev.ports && ev.ports[0];
    if (!port) return;
    Log.Info('msgport: received MessagePort from parent');
    if (portWaiter) {
        const w = portWaiter;
        portWaiter = null;
        w(port);
    } else {
        pendingPort = port;
    }
});

function nextPort() {
    if (pendingPort) {
        const p = pendingPort;
        pendingPort = null;
        return Promise.resolve(p);
    }
    return new Promise((resolve) => { portWaiter = resolve; });
}

class MessagePortChannel {
    constructor(port) {
        this._port = port;
        this.binaryType = 'arraybuffer';
        this.protocol = '';
        this.readyState = 'open';
        this.onerror = () => {};
        this.onmessage = () => {};
        this.onopen = () => {};
        this.onclose = () => {};

        port.onmessage = (ev) => {
            if (ev.data instanceof ArrayBuffer) {
                this.onmessage({ data: ev.data });
                return;
            }
            if (ev.data && ev.data.type === 'close') {
                Log.Info('msgport: parent closed transport: ' + (ev.data.reason || ''));
                this.readyState = 'closed';
                this.onclose({ code: 1000, reason: ev.data.reason || 'transport closed' });
            }
        };
        port.start?.();
    }

    send(data) {
        if (this.readyState !== 'open') return;
        // Websock hands us an ArrayBuffer view of its send queue — copy, the
        // queue is reused immediately after.
        const ab = data instanceof ArrayBuffer
            ? data.slice(0)
            : data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
        this._port.postMessage(ab, [ab]);
    }

    close() {
        if (this.readyState === 'closed') return;
        this.readyState = 'closed';
        try { this._port.postMessage({ type: 'close' }); } catch (e) { /* ignore */ }
        try { this._port.close(); } catch (e) { /* ignore */ }
    }
}

// Patch Websock.open: the "msgport:" URI selects this transport. Everything
// else falls through to the original WebSocket path.
const _origOpen = Websock.prototype.open;
Websock.prototype.open = function (uri, protocols) {
    // Matches either a bare "msgport:" URI or noVNC's host-based URL build
    // landing on .../msgport (ard.html?path=msgport).
    if (typeof uri === 'string' && (uri.startsWith('msgport:') || /\/msgport$/.test(uri))) {
        Log.Info('msgport: waiting for MessagePort transport');
        nextPort().then((port) => {
            const chan = new MessagePortChannel(port);
            this.attach(chan);
            // attach() wires onopen but a MessagePort has no async handshake —
            // fire it on the next tick so RFB's handlers are installed first.
            setTimeout(() => chan.onopen(), 0);
        });
        return;
    }
    return _origOpen.call(this, uri, protocols);
};

Log.Info('msgport transport registered');
