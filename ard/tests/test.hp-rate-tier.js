import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { TierController, DOWN_MIN_GAP_MS, UP_LOSS_PCT } from '../hp/rate-tier.js';

const GOOD = { lossPct: 0, queueDelayMs: 0, videoKbit: 20000, budget: null, recovery: false };

// Feed `seconds` one-second samples starting after `t`; returns {t, changes}.
function run(c, t, seconds, over = {}, step = 1000) {
    const changes = [];
    for (let i = 0; i < seconds * 1000 / step; i++) {
        t += step;
        const r = c.sample({ now: t, ...GOOD, ...over });
        if (r !== null) changes.push(r);
    }
    return { t, changes };
}

describe('HP tier controller', () => {
    it('starts at 16000 and caps the start by maxKbit', () => {
        assert.equal(new TierController({}).tier, 16000);
        assert.equal(new TierController({ maxKbit: 13000 }).tier, 12000);
    });

    it('steps down on loss, delay and recovery to 0.75 x tier', () => {
        for (const over of [{ lossPct: 4 }, { queueDelayMs: 200, lossPct: UP_LOSS_PCT },
                            { recovery: true }]) {
            const c = new TierController({});
            assert.equal(c.sample({ now: 1000, ...GOOD, ...over }), 12000);
            assert.equal(c.tier, 12000);
        }
    });

    // The delay reading is arrival minus the Mac's RTP time, so a Mac clock
    // or stamping that runs slow reads as a standing queue (about 1.5 s seen
    // with a clean path). Delay steps down only when the path shows stress.
    it('delay alone on a clean path does not step down', () => {
        const c = new TierController({});
        const { changes } = run(c, 0, 30, { queueDelayMs: 1500, lossPct: 0.8 });
        assert.deepEqual(changes, []);
        assert.equal(c.tier, 16000);
    });

    it('delay steps down with loss or a limiting budget behind it', () => {
        const withLoss = new TierController({});
        assert.equal(withLoss.sample({ now: 1000, ...GOOD, queueDelayMs: 200, lossPct: UP_LOSS_PCT }), 12000);
        // A limiting budget too high to trip on its own still confirms the queue.
        const withBudget = new TierController({});
        assert.equal(withBudget.sample({ now: 1000, ...GOOD, queueDelayMs: 200,
            budget: { kbit: 20000, limiting: true } }), 12000);
    });

    it('a limiting budget lowers the target to 0.85 x budget', () => {
        const c = new TierController({});
        assert.equal(c.sample({ now: 1000, ...GOOD, budget: { kbit: 9000, limiting: true } }), 6000);
    });

    it('ignores a non-limiting budget', () => {
        const c = new TierController({});
        assert.equal(c.sample({ now: 1000, ...GOOD, budget: { kbit: 2000, limiting: false } }), null);
        assert.equal(c.tier, 16000);
    });

    it('a limiting budget above 0.9 x tier is no trigger', () => {
        const c = new TierController({});
        assert.equal(c.sample({ now: 1000, ...GOOD, budget: { kbit: 15000, limiting: true } }), null);
    });

    it('allows one down per 4 s', () => {
        const c = new TierController({});
        assert.equal(c.sample({ now: 1000, ...GOOD, lossPct: 5 }), 12000);
        assert.equal(c.sample({ now: 1000 + DOWN_MIN_GAP_MS - 1, ...GOOD, lossPct: 5 }), null);
        assert.equal(c.tier, 12000);
        assert.equal(c.sample({ now: 1000 + DOWN_MIN_GAP_MS, ...GOOD, lossPct: 5 }), 8000);
        assert.equal(c.tier, 8000);
    });

    it('steps up one tier after 30 s clean under load', () => {
        const c = new TierController({});
        const { changes } = run(c, 0, 31);
        assert.deepEqual(changes, [20000]);
    });

    it('does not count time between sparse samples as continuous 1 Hz', () => {
        const c = new TierController({});
        // 5 s cadence, 40 s: loaded the whole time, still goes up once.
        assert.deepEqual(run(c, 0, 40, {}, 5000).changes, [20000]);
    });

    it('never raises the tier on an idle screen', () => {
        const c = new TierController({});
        assert.deepEqual(run(c, 0, 120, { videoKbit: 500 }).changes, []);
    });

    it('needs 20 loaded seconds, not just 30 clean ones', () => {
        const c = new TierController({});
        let r = run(c, 0, 15, { videoKbit: 500 });
        r = run(c, r.t, 19);
        assert.deepEqual(r.changes, []);
        r = run(c, r.t, 2);
        assert.deepEqual(r.changes, [20000]);
    });

    it('loss of 1% or more restarts the clean window', () => {
        const c = new TierController({});
        let r = run(c, 0, 25);
        r = run(c, r.t, 1, { lossPct: 1.5 });
        r = run(c, r.t, 25);
        assert.deepEqual(r.changes, []);
    });

    it('a limiting budget of any size blocks an up; a non-limiting one does not', () => {
        const c = new TierController({});
        assert.deepEqual(run(c, 0, 120, { budget: { kbit: 20000, limiting: true } }).changes, []);
        assert.deepEqual(run(c, 120000, 120, { budget: { kbit: 1e9, limiting: true } }).changes, []);
        assert.deepEqual(run(c, 240000, 5, { budget: { kbit: 1000, limiting: false } }).changes, [20000]);
    });

    it('doubles the hold after each down, capped at 120 s', () => {
        const c = new TierController({ start: 20000 });
        let r = { t: 0 };
        const down = (from, to) => {
            r = run(c, r.t, 1, { lossPct: 5 });
            assert.equal(c.tier, to, `down from ${from}`);
        };
        down(20000, 12000);
        r = run(c, r.t, 55);
        assert.equal(c.tier, 12000);
        r = run(c, r.t, 10);
        assert.equal(c.tier, 16000);
        down(16000, 12000);
        r = run(c, r.t, 115);
        assert.equal(c.tier, 12000);
        r = run(c, r.t, 10);
        assert.equal(c.tier, 16000);
        down(16000, 12000);
        r = run(c, r.t, 115);
        assert.equal(c.tier, 12000);
        r = run(c, r.t, 10);
        assert.equal(c.tier, 16000);
    });

    it('resets the hold to 30 s after 10 minutes without a down trigger, mid-climb', () => {
        const c = new TierController({ start: 16000 });
        let r = run(c, 0, 1, { lossPct: 5 });          // 12000, hold 60
        r = run(c, r.t, 60);                            // up to 16000
        assert.equal(c.tier, 16000);
        r = run(c, r.t, 1, { lossPct: 5 });             // 12000, hold 120
        assert.equal(c.tier, 12000);
        const T = r.t;
        r = run(c, r.t, 580, { videoKbit: 100 });      // idle: no up
        assert.equal(c.tier, 12000);
        r = run(c, r.t, 20);                            // hold reset at T+600: up at once
        assert.equal(r.t, T + 600000);
        assert.equal(c.tier, 16000);
        r = run(c, r.t, 31);                            // and the next hold is 30 s, not 120
        assert.equal(c.tier, 20000);
    });

    it('snaps a start that is not a tier down, and a tiny cap to 6000', () => {
        assert.equal(new TierController({ start: 14000 }).tier, 12000);
        assert.equal(new TierController({ maxKbit: 3000 }).tier, 6000);
    });

    it('caps at 6000 when ardHpMaxKbit is below the lowest tier', () => {
        const c = new TierController({ maxKbit: 4000 });
        assert.equal(c.tier, 6000);
        assert.equal(c.sample({ now: 1000, ...GOOD, lossPct: 9 }), null);
        assert.equal(c.tier, 6000);
        assert.deepEqual(run(c, 1000, 200).changes, [], 'the cap also holds the ceiling at 6000');
    });

    it('steps down 20000 -> 12000 -> 8000 -> 6000 -> stays', () => {
        const c = new TierController({ start: 20000 });
        assert.equal(c.sample({ now: 1000, ...GOOD, lossPct: 5 }), 12000);
        assert.equal(c.sample({ now: 1000 + DOWN_MIN_GAP_MS, ...GOOD, lossPct: 5 }), 8000);
        assert.equal(c.sample({ now: 1000 + 2 * DOWN_MIN_GAP_MS, ...GOOD, lossPct: 5 }), 6000);
        assert.equal(c.sample({ now: 1000 + 3 * DOWN_MIN_GAP_MS, ...GOOD, recovery: true }), null);
        assert.equal(c.tier, 6000);
    });

    it('treats an invalid maxKbit as no cap', () => {
        for (const m of [NaN, 0, -5, Infinity]) {
            assert.equal(new TierController({ start: 20000, maxKbit: m }).tier, 20000);
        }
    });

    it('missing or NaN measurements earn no up credit', () => {
        const c = new TierController({});
        assert.deepEqual(run(c, 0, 120, { lossPct: NaN }).changes, []);
        assert.deepEqual(run(c, 120000, 120, { queueDelayMs: undefined }).changes, []);
        assert.deepEqual(run(c, 240000, 120, { videoKbit: NaN }).changes, []);
        assert.equal(c.tier, 16000);
    });

    it('ignores a backwards clock when crediting load', () => {
        const c = new TierController({});
        c.sample({ now: 10000, ...GOOD });
        c.sample({ now: 5000, ...GOOD });
        c.sample({ now: 11000, ...GOOD });
        assert.equal(c._loadMs, 1000);
    });

    it('never exceeds the ceiling or maxKbit and never drops below 6000', () => {
        const c = new TierController({ maxKbit: 12000 });
        assert.equal(c.tier, 12000);
        assert.deepEqual(run(c, 0, 200, { videoKbit: 12000 }).changes, []);
        const d = new TierController({ start: 6000 });
        assert.equal(d.sample({ now: 1000, ...GOOD, lossPct: 9 }), null);
        assert.equal(d.tier, 6000);
        const e = new TierController({});
        e.sample({ now: 1000, ...GOOD, budget: { kbit: 100, limiting: true } });
        assert.equal(e.tier, 6000);
    });
});
