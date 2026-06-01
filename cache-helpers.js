/**
 * Pure helpers for player-daemon cache management.
 *
 * Extracted from server.js so the decision logic for #111 (cache eviction +
 * disk usage telemetry) can be exercised by unit tests without spinning
 * up MQTT, the express app, or the OTel telemetry pipeline.
 *
 * These functions take all dependencies as inputs and return plain values —
 * no I/O, no globals, no time. server.js is responsible for actually
 * touching the filesystem with the result.
 */

/**
 * Decide which files in CACHE_DIR are stale and should be deleted.
 *
 * @param {Object}        params
 * @param {string[]}      params.files            All filenames found in CACHE_DIR (basenames, not paths)
 * @param {Set<string>}   params.activeAssetPaths Basenames currently referenced by the playlist — must NOT be evicted
 * @param {Set<string>}   params.protectedFiles   Filenames that must never be evicted regardless of playlist state
 * @returns {string[]} Subset of `files` that are safe to delete
 */
function selectStaleFiles({ files, activeAssetPaths, protectedFiles }) {
    if (!Array.isArray(files)) return [];
    const active = activeAssetPaths instanceof Set ? activeAssetPaths : new Set(activeAssetPaths || []);
    const protectedSet = protectedFiles instanceof Set ? protectedFiles : new Set(protectedFiles || []);

    const stale = [];
    for (const file of files) {
        if (typeof file !== 'string' || file.length === 0) continue;
        // Never touch protected files (state.json, api-token, MQTT creds, etc.)
        if (protectedSet.has(file)) continue;
        // Never touch in-progress downloads.
        if (file.endsWith('.tmp')) continue;
        // Keep anything currently referenced by the active playlist.
        if (active.has(file)) continue;
        stale.push(file);
    }
    return stale;
}

/**
 * Compute disk-usage percentage from a `fs.statfs()` result.
 *
 * Returns null when the stat object is missing required fields or when
 * `blocks` is zero (statfs not implemented on this platform).
 *
 * @param {{blocks?: number, bfree?: number}} stat statfs result
 * @returns {number|null} Used percentage (0 — 100) or null when unknown
 */
function computeDiskUsagePct(stat) {
    if (!stat || typeof stat.blocks !== 'number' || typeof stat.bfree !== 'number') return null;
    if (stat.blocks <= 0) return null;
    if (stat.bfree < 0 || stat.bfree > stat.blocks) return null;
    const used = (stat.blocks - stat.bfree) / stat.blocks;
    return used * 100;
}

/**
 * Whether disk usage warrants a DISK_HIGH MQTT telemetry alert.
 *
 * @param {number|null} usedPct Percentage from computeDiskUsagePct()
 * @param {number}      [threshold=80] Trigger threshold (default matches server.js)
 * @returns {boolean}
 */
function shouldAlertDiskHigh(usedPct, threshold = 80) {
    return typeof usedPct === 'number' && Number.isFinite(usedPct) && usedPct > threshold;
}

module.exports = {
    selectStaleFiles,
    computeDiskUsagePct,
    shouldAlertDiskHigh,
};
