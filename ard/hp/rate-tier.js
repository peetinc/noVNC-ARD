/*
 * HP bitrate tier controller.
 *
 * Chooses the tier (kbit/s) the browser offers the Mac. Pure: no timers; the
 * caller passes `now` (ms) with each sample, roughly once a second. Inputs
 * come from ReceiveStats.window() (lossPct; queueDelayMs, a standing queue:
 * the least per-picture delay of the last second, so one large picture and
 * the pictures queued behind it do not count; videoKbit, which counts RTP
 * payload bytes only), the latest agent budget {kbit, limiting} or null,
 * and a recovery flag.
 *
 * Down: loss, recovery, a limiting budget below BUDGET_DOWN x tier, or
 * queuing delay with stress behind it (loss >= UP_LOSS_PCT or any limiting
 * budget) -> the highest tier <= min(0.75 x tier, BUDGET_TARGET x budget),
 * at most one per DOWN_MIN_GAP_MS. Delay alone is no evidence: it is arrival
 * minus the Mac's RTP time, and a Mac clock or stamping that runs slow reads
 * as a standing queue on a clean path.
 * Up: one step after UP_HOLD_MS with no trigger and loss < UP_LOSS_PCT, with
 * video at least UP_LOAD_FRACTION x tier for UP_LOAD_SECONDS of that time
 * (an idle screen proves nothing), and only while the agent budget is absent
 * or not limiting. Each down doubles the hold; UP_RESET_MS without a down
 * trigger resets it.
 */

import { TIERS, DEFAULT_TIER } from './offer-template.js';

export const DOWN_LOSS_PCT = 3;
export const DOWN_DELAY_MS = 150;
export const DOWN_MIN_GAP_MS = 4000;
export const UP_HOLD_MS = [30000, 60000, 120000];
export const UP_RESET_MS = 600000;
export const UP_LOSS_PCT = 1;
export const UP_LOAD_FRACTION = 0.7;
export const UP_LOAD_SECONDS = 20;
export const BUDGET_DOWN = 0.9;
export const BUDGET_TARGET = 0.85;

const DOWN_FACTOR = 0.75;
// A sample gap longer than this credits no more load time than this, so a
// stalled tick cannot fake sustained load.
const MAX_CREDIT_MS = 5000;

// Highest tier <= kbit, never below the lowest tier.
function floorTier(kbit) {
    let best = TIERS[0];
    for (const t of TIERS) {
        if (t <= kbit) best = t;
    }
    return best;
}

export class TierController {
    constructor({ start = 16000, maxKbit = null } = {}) {
        const capped = Number.isFinite(maxKbit) && maxKbit > 0;
        this._ceiling = capped ? Math.min(DEFAULT_TIER, floorTier(maxKbit)) : DEFAULT_TIER;
        this._tier = Math.min(floorTier(Number.isFinite(start) ? start : 16000), this._ceiling);
        this._holdIdx = 0;
        this._lastDownAt = null;
        this._lastTriggerAt = null; // last down trigger (not reset by an up)
        this._windowStart = null;   // start of the current trigger-free window
        this._lastNow = null;
        this._loadMs = 0;           // loaded time inside the window
    }

    get tier() { return this._tier; }

    sample({ now, lossPct, queueDelayMs, videoKbit, budget = null, recovery = false }) {
        const dt = this._lastNow === null ? 0 : Math.min(Math.max(now - this._lastNow, 0), MAX_CREDIT_MS);
        if (this._lastNow === null || now >= this._lastNow) this._lastNow = now;
        if (this._windowStart === null) this._windowStart = now;
        if (this._lastTriggerAt === null) this._lastTriggerAt = now;

        const limiting = budget !== null && budget.limiting === true;
        const budgetKbit = limiting && Number.isFinite(budget.kbit) ? budget.kbit : null;
        const budgetTrips = budgetKbit !== null && budgetKbit < BUDGET_DOWN * this._tier;
        const stressed = limiting || lossPct >= UP_LOSS_PCT;
        const trigger = budgetTrips || recovery ||
            lossPct > DOWN_LOSS_PCT || (queueDelayMs > DOWN_DELAY_MS && stressed);

        if (trigger) {
            this._lastTriggerAt = now;
            this._restartWindow(now);
            if (this._lastDownAt !== null && now - this._lastDownAt < DOWN_MIN_GAP_MS) return null;
            let target = DOWN_FACTOR * this._tier;
            if (budgetKbit !== null) target = Math.min(target, BUDGET_TARGET * budgetKbit);
            const next = Math.min(floorTier(target), this._tier);
            if (next === this._tier) return null;
            this._tier = next;
            this._lastDownAt = now;
            this._holdIdx = Math.min(this._holdIdx + 1, UP_HOLD_MS.length - 1);
            return next;
        }

        // Missing or non-finite measurements are not evidence of a clean path.
        if (!Number.isFinite(lossPct) || !Number.isFinite(queueDelayMs) || lossPct >= UP_LOSS_PCT) {
            this._restartWindow(now);
            return null;
        }

        if (now - this._lastTriggerAt >= UP_RESET_MS) this._holdIdx = 0;
        if (Number.isFinite(videoKbit) && videoKbit >= UP_LOAD_FRACTION * this._tier) this._loadMs += dt;

        const idx = TIERS.indexOf(this._tier);
        const next = TIERS[idx + 1];
        if (next === undefined || next > this._ceiling) return null;
        if (now - this._windowStart < UP_HOLD_MS[this._holdIdx]) return null;
        if (this._loadMs < UP_LOAD_SECONDS * 1000) return null;
        if (limiting) return null;

        this._tier = next;
        this._windowStart = now;
        this._loadMs = 0;
        return next;
    }

    _restartWindow(now) {
        this._windowStart = now;
        this._loadMs = 0;
    }
}
