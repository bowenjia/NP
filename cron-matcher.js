/**
 * Offline Dayparting — Lightweight cron matcher (no external dependencies).
 *
 * Supports standard 5-field cron: minute hour dayOfMonth month dayOfWeek
 *
 * Field syntax:
 *   *        — any value
 *   5        — exact value
 *   1-5      — inclusive range
 *   1,3,5    — list
 *   * /5      — step (every 5) — written without space, shown here to avoid comment issues
 *   1-10/2   — range with step
 */

'use strict';

/**
 * Parse a single cron field and return the set of matching integer values.
 * @param {string} field  — one of the 5 cron tokens
 * @param {number} min    — minimum legal value (inclusive)
 * @param {number} max    — maximum legal value (inclusive)
 * @returns {Set<number>}
 */
function parseField(field, min, max) {
    const values = new Set();

    // A field can be a comma-separated list of atoms: "1,3,5" or "1-3,7"
    const parts = field.split(',');

    for (const part of parts) {
        // Check for step:  "*/5" or "1-10/2"
        let [range, stepStr] = part.split('/');
        const step = stepStr ? parseInt(stepStr, 10) : 1;

        if (range === '*') {
            for (let i = min; i <= max; i += step) {
                values.add(i);
            }
        } else if (range.includes('-')) {
            const [lo, hi] = range.split('-').map(Number);
            for (let i = lo; i <= hi; i += step) {
                values.add(i);
            }
        } else {
            // Single number, possibly with step (rare but valid: "5/2" starting at 5)
            const start = parseInt(range, 10);
            if (step === 1) {
                values.add(start);
            } else {
                for (let i = start; i <= max; i += step) {
                    values.add(i);
                }
            }
        }
    }

    return values;
}

/**
 * Return true if `cronExpression` matches at the given `date`.
 *
 * @param {string} cronExpression  — 5-field cron string
 * @param {Date}   [date]          — defaults to now
 * @returns {boolean}
 */
function matchesCron(cronExpression, date) {
    if (!cronExpression || typeof cronExpression !== 'string') return true;

    date = date || new Date();

    const tokens = cronExpression.trim().split(/\s+/);
    if (tokens.length !== 5) {
        // Malformed expression — treat as "always eligible" to avoid silently hiding content
        return true;
    }

    const [minField, hourField, domField, monthField, dowField] = tokens;

    const minute    = date.getMinutes();
    const hour      = date.getHours();
    const dayOfMonth = date.getDate();
    const month     = date.getMonth() + 1;          // JS months 0-11 → cron 1-12
    const dayOfWeek = date.getDay();                 // JS 0=Sun … 6=Sat (matches cron)

    if (!parseField(minField,   0, 59).has(minute))       return false;
    if (!parseField(hourField,  0, 23).has(hour))         return false;
    if (!parseField(domField,   1, 31).has(dayOfMonth))   return false;
    if (!parseField(monthField, 1, 12).has(month))        return false;
    if (!parseField(dowField,   0,  6).has(dayOfWeek))    return false;

    return true;
}

module.exports = { matchesCron, parseField };
