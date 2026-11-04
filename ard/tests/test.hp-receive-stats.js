/*
 * Unit tests for receive statistics: the loss, jitter and queuing delay a
 * receiver report and the tier controller are built from.
 *
 * Run: node --test ard/tests/test.hp-receive-stats.js
 */

import { describe, it } from 'node:test';
import { strictEqual, ok, deepStrictEqual } from 'node:assert';

import { ReceiveStats, DELAY_MIN_SAMPLES } from '../hp/receive-stats.js';
import { TierController, DOWN_DELAY_MS, UP_LOSS_PCT } from '../hp/rate-tier.js';

const VIDEO = 90000;
const SSRC = 0x1234;
// 60 pictures a second: RTP time 1500 apart at 90 kHz.
const PICTURE_TS = 1500;
const PICTURE_MS = 1000 / 60;
// Steady transit of the baseline.
const TRANSIT_MS = 30;

// Feed `count` packets from `first`, `stepMs` apart, skipping `missing`.
function feed(stats, { first = 0, count, missing = [], t0 = 0, stepMs = 10, ssrc = SSRC,
                       clockRate = VIDEO, bytes = 1000, video = true, extraMs = () => 0 }) {
    for (let i = first; i < first + count; i++) {
        if (missing.includes(i)) continue;
        stats.onPacket({
            ssrc, seq: i & 0xffff, rtpTs: ((i * stepMs * clockRate) / 1000) >>> 0, clockRate, bytes,
            now: t0 + i * stepMs + extraMs(i), video,
        });
    }
}

// Sends picture `n` (RTP time n x PICTURE_TS) on one SSRC: `packets`
// packets from `at`, `spreadMs` apart.
function pictureSender(stats, ssrc = SSRC) {
    let seq = 0;
    return (n, at, packets = 1, spreadMs = 1) => {
        for (let k = 0; k < packets; k++) {
            stats.onPacket({ ssrc, seq: seq++ & 0xffff, rtpTs: (n * PICTURE_TS) >>> 0, clockRate: VIDEO,
                             bytes: 1000, now: at + k * spreadMs, video: true });
        }
    };
}

// When picture `n` would arrive with no queue at all.
const onTime = n => n * PICTURE_MS + TRANSIT_MS;

// Samples the controller from the window at `now`; collects its changes.
function sampleInto(ctl, stats, now, changes, over = {}) {
    const w = stats.window(now);
    const r = ctl.sample({ now, ...w, videoKbit: 20000, ...over });
    if (r !== null) changes.push(r);
    return w;
}

describe('ReceiveStats receiver report fields', () => {
    it('counts missing packets and the fraction since the previous report', () => {
        const stats = new ReceiveStats();
        feed(stats, { count: 100, missing: [10, 11, 12, 13, 14] });
        const a = stats.rrFields(SSRC);
        strictEqual(a.cumulativeLost, 5);
        strictEqual(a.fractionLost, Math.floor(5 * 256 / 100));
        strictEqual(a.highestSeq, 99);
        feed(stats, { first: 100, count: 100 });
        const b = stats.rrFields(SSRC);
        strictEqual(b.fractionLost, 0);
        strictEqual(b.cumulativeLost, 5);
        strictEqual(b.highestSeq, 199);
    });

    it('knows nothing of a stream it has not seen', () => {
        strictEqual(new ReceiveStats().rrFields(SSRC), null);
    });

    it('counts no loss across sequence wraparound and extends the highest', () => {
        const stats = new ReceiveStats();
        for (let i = 0; i < 12; i++) {
            stats.onPacket({ ssrc: SSRC, seq: (65530 + i) & 0xffff, rtpTs: i * 900, clockRate: VIDEO,
                             bytes: 100, now: i * 10, video: true });
        }
        const r = stats.rrFields(SSRC);
        strictEqual(r.cumulativeLost, 0);
        strictEqual(r.fractionLost, 0);
        strictEqual(r.highestSeq, 65530 + 11);
    });

    it('does not count a late or duplicate packet as a new loss', () => {
        const stats = new ReceiveStats();
        const p = (seq, now) => stats.onPacket({ ssrc: SSRC, seq, rtpTs: seq * 900, clockRate: VIDEO,
                                                 bytes: 1, now, video: true });
        p(0, 0); p(1, 10); p(3, 30); p(2, 35); p(2, 36); p(4, 40);
        const r = stats.rrFields(SSRC);
        strictEqual(r.highestSeq, 4);
        strictEqual(r.cumulativeLost, 0);
    });

    it('computes interarrival jitter by RFC 3550 section 6.4.1', () => {
        const stats = new ReceiveStats();
        const extra = (i) => (i % 2 ? 2 : 0);
        feed(stats, { count: 200, extraMs: extra });
        let jitter = 0, prev = null;
        for (let i = 0; i < 200; i++) {
            const transit = (i * 10 + extra(i)) * VIDEO / 1000 - i * 900;
            if (prev !== null) jitter += (Math.abs(transit - prev) - jitter) / 16;
            prev = transit;
        }
        strictEqual(stats.rrFields(SSRC).jitter, Math.floor(jitter));
        ok(jitter > 100, 'a 2 ms swing is 180 units, got ' + jitter);
    });

    it('reports loss on every stripe under the first stripe\'s SSRC', () => {
        const stats = new ReceiveStats();
        const all = [0, 1, 2, 3].map(i => SSRC + i);
        for (const ssrc of all) feed(stats, { count: 100, ssrc, missing: ssrc === SSRC + 2 ? [10, 11, 12, 13, 14, 15, 16, 17, 18, 19] : [] });
        const a = stats.rrFields(SSRC, all);
        strictEqual(a.cumulativeLost, 10);
        strictEqual(a.fractionLost, Math.floor(10 * 256 / 400));
        // Each stripe's interval advanced once: a clean second interval reads 0.
        for (const ssrc of all) feed(stats, { first: 100, count: 100, ssrc });
        const b = stats.rrFields(SSRC, all);
        strictEqual(b.fractionLost, 0);
        strictEqual(b.cumulativeLost, 10);
    });

    it('keeps the first stripe\'s highestSeq and jitter', () => {
        const stats = new ReceiveStats();
        feed(stats, { count: 50, ssrc: SSRC });
        feed(stats, { count: 80, ssrc: SSRC + 1, extraMs: i => (i % 2 ? 3 : 0) });
        const one = new ReceiveStats();
        feed(one, { count: 50, ssrc: SSRC });
        const r = stats.rrFields(SSRC, [SSRC, SSRC + 1]);
        strictEqual(r.highestSeq, 49);
        strictEqual(r.jitter, one.rrFields(SSRC).jitter);
    });

    it('skips stripes it has not seen and nulls without the first', () => {
        const stats = new ReceiveStats();
        feed(stats, { count: 10, ssrc: SSRC + 1, missing: [3] });
        strictEqual(stats.rrFields(SSRC, [SSRC, SSRC + 1]), null);
        feed(stats, { count: 10, ssrc: SSRC });
        strictEqual(stats.rrFields(SSRC, [SSRC, SSRC + 1, SSRC + 2]).cumulativeLost, 1);
    });

    it('keeps each SSRC apart', () => {
        const stats = new ReceiveStats();
        feed(stats, { count: 50, ssrc: 1, missing: [3] });
        feed(stats, { count: 50, ssrc: 2, clockRate: 48000, video: false });
        strictEqual(stats.rrFields(1).cumulativeLost, 1);
        strictEqual(stats.rrFields(2).cumulativeLost, 0);
    });
});

describe('ReceiveStats window', () => {
    it('reports loss across all video SSRCs, not audio', () => {
        const stats = new ReceiveStats();
        feed(stats, { count: 100, missing: [20, 50, 80], stepMs: 15 });
        feed(stats, { count: 100, ssrc: 0x99, clockRate: 48000, video: false, missing: [5, 6, 7, 8] });
        const w = stats.window(1500);
        strictEqual(w.lossPct, 3);
    });

    it('sums loss over two stripes', () => {
        const stats = new ReceiveStats();
        feed(stats, { count: 100, ssrc: 1, stepMs: 15 });
        feed(stats, { count: 100, ssrc: 2, stepMs: 15, missing: [10, 11, 12, 13, 14, 15, 16, 17, 18, 19] });
        const w = stats.window(1500);
        strictEqual(w.lossPct, 5);
    });

    it('forgets packets older than two seconds', () => {
        const stats = new ReceiveStats();
        feed(stats, { count: 100, missing: [30, 31], stepMs: 10 });
        ok(stats.window(1000).lossPct > 0);
        strictEqual(stats.window(5000).lossPct, 0);
        strictEqual(stats.window(5000).videoKbit, 0);
    });

    it('reads a standing queuing delay above the 10 s baseline', () => {
        const stats = new ReceiveStats();
        feed(stats, { count: 1000, stepMs: 10, extraMs: () => 30 });   // 10 s at a steady 30 ms transit
        feed(stats, { first: 1000, count: 150, stepMs: 10, extraMs: () => 230 });
        const w = stats.window(11490 + 230);
        ok(Math.abs(w.queueDelayMs - 200) < 1, 'about 200, got ' + w.queueDelayMs);
        strictEqual(stats.window(20000).queueDelayMs, 0);
    });

    it('takes delay once per picture, and needs several pictures in the last second', () => {
        const stats = new ReceiveStats();
        const send = pictureSender(stats);
        for (let n = 0; n < 600; n++) send(n, onTime(n));
        // An idle screen for 1.5 s, then a key picture of 300 packets, all
        // one RTP time, arriving 200 ms late over 300 ms: one sample, not 300.
        const late = n => onTime(n) + 200;
        send(690, late(690), 300, 1);
        strictEqual(stats.window(late(690) + 300).queueDelayMs, 0);
        // Late packets of older pictures are no delay samples either.
        for (let n = 686; n < 690; n++) send(n, late(690) + 300 + (n - 685));
        strictEqual(stats.window(late(690) + 305).queueDelayMs, 0);
        // New pictures are; with DELAY_MIN_SAMPLES of them the delay shows.
        for (let n = 691; n < 690 + DELAY_MIN_SAMPLES - 1; n++) send(n, late(n));
        strictEqual(stats.window(late(690 + DELAY_MIN_SAMPLES - 2)).queueDelayMs, 0);
        const last = 690 + DELAY_MIN_SAMPLES - 1;
        send(last, late(last));
        ok(Math.abs(stats.window(late(last)).queueDelayMs - 200) < 1);
    });

    it('a large picture and the pictures queued behind it are no reason to step down', () => {
        const stats = new ReceiveStats();
        const send = pictureSender(stats);
        const ctl = new TierController({});
        const changes = [];
        for (let n = 0; n < 600; n++) send(n, onTime(n));
        // Picture 600 is 300 packets the Mac sends over 300 ms; the 60 per
        // second after it wait until it is out, then go 1 ms apart.
        let free = onTime(600);
        send(600, free, 300, 1);
        free += 300;
        let worstPicture = 0, worst = 0;
        for (let n = 601; n < 720; n++) {
            const at = Math.max(onTime(n), free);
            free = at + 1;
            send(n, at);
            worstPicture = Math.max(worstPicture, at - onTime(n));
            worst = Math.max(worst, sampleInto(ctl, stats, at, changes).queueDelayMs);
        }
        ok(worstPicture > DOWN_DELAY_MS, 'pictures behind it are late, ' + worstPicture + ' ms');
        ok(worst < 1, 'no standing queue, got ' + worst);
        strictEqual(changes.length, 0);
        strictEqual(ctl.tier, 16000);
    });

    it('a large picture over four stripes is no reason to step down', () => {
        const stats = new ReceiveStats();
        const sends = [1, 2, 3, 4].map(ssrc => pictureSender(stats, ssrc));
        const ctl = new TierController({});
        const changes = [];
        for (let n = 0; n < 600; n++) sends.forEach((send, s) => send(n, onTime(n) + s * 0.5));
        // Picture 600 on every stripe, one stripe after another, 75 ms each:
        // the last stripe's first packet is 225 ms behind the first's.
        let free = onTime(600);
        for (const send of sends) {
            send(600, free, 75, 1);
            free += 75;
        }
        let worst = 0;
        for (let n = 601; n < 720; n++) {
            sends.forEach((send, s) => {
                const at = Math.max(onTime(n) + s * 0.5, free);
                free = at + 0.25;
                send(n, at);
                worst = Math.max(worst, sampleInto(ctl, stats, at, changes).queueDelayMs);
            });
        }
        ok(worst < 1, 'no standing queue, got ' + worst);
        strictEqual(changes.length, 0);
        strictEqual(ctl.tier, 16000);
    });

    it('a second of pictures all 200 ms late is a queue, and steps down with loss behind it', () => {
        const stats = new ReceiveStats();
        const send = pictureSender(stats);
        const ctl = new TierController({});
        const changes = [];
        for (let n = 0; n < 600; n++) send(n, onTime(n));
        let firstLate = null, downAt = null;
        for (let n = 600; n < 680; n++) {
            const at = onTime(n) + 200;
            if (firstLate === null) firstLate = at;
            send(n, at);
            sampleInto(ctl, stats, at, changes, { lossPct: UP_LOSS_PCT });
            if (downAt === null && changes.length > 0) downAt = at;
        }
        deepStrictEqual(changes, [12000]);
        // Not before the on-time pictures have left the last second.
        ok(downAt - onTime(599) > 1000, 'down ' + (downAt - onTime(599)) + ' ms after the last on-time picture');
        ok(Math.abs(stats.window(onTime(679) + 200).queueDelayMs - 200) < 1);
    });

    // Pictures 15% further apart in arrival than in RTP time: a Mac clock or
    // stamping that runs slow, on a path with no queue at all. It reads as a
    // growing delay (the field saw about 1.5 s); without loss or a limiting
    // budget behind it, it must not step down.
    it('a slow Mac RTP clock reads as delay but does not step down', () => {
        const stats = new ReceiveStats();
        const send = pictureSender(stats);
        const ctl = new TierController({});
        const changes = [];
        let worst = 0;
        for (let n = 0; n < 1800; n++) {
            const at = n * PICTURE_MS * 1.15 + TRANSIT_MS;
            send(n, at);
            worst = Math.max(worst, sampleInto(ctl, stats, at, changes).queueDelayMs);
        }
        ok(worst > 1000, 'skew reads as delay, ' + worst + ' ms');
        // Over 30 s of loaded clean path the controller may step up; never down.
        ok(changes.every(t => t > 16000), 'changes ' + changes);
    });

    it('is not fooled by the 32-bit timestamp wrapping', () => {
        const stats = new ReceiveStats();
        for (let i = 0; i < 100; i++) {
            stats.onPacket({ ssrc: SSRC, seq: i, rtpTs: (0xffffff00 + i * 900) >>> 0, clockRate: VIDEO,
                             bytes: 10, now: i * 10, video: true });
        }
        ok(stats.window(1000).queueDelayMs < 1);
    });

    it('measures video bit rate from bytes over the window', () => {
        const stats = new ReceiveStats();
        feed(stats, { count: 300, stepMs: 10, bytes: 1250 });     // 1000 kbit/s for 3 s
        const w = stats.window(2990);
        ok(Math.abs(w.videoKbit - 1000) < 20, 'about 1000, got ' + w.videoKbit);
    });
});
