// Persistent structured store backed by JSON files.
// Provides publication cache (≥2 versions, 7-day retention), schedule cache,
// and datasource cache so the player can operate fully offline for 7 days.
const path = require('path');
const fs = require('fs-extra');

const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_PUBLICATIONS = 2;

class SqliteStore {
    constructor(cacheDir) {
        this._pubFile = path.join(cacheDir, 'publications.json');
        this._scheduleFile = path.join(cacheDir, 'schedules.json');
        this._dsFile = path.join(cacheDir, 'datasources.json');
    }

    _read(file) {
        try {
            return fs.readJsonSync(file, { throws: false }) || [];
        } catch { return []; }
    }

    _write(file, data) {
        try { fs.writeJsonSync(file, data); } catch (err) { console.error('[STORE] Failed to write to ' + file + ':', err.message); }
    }

    // Keep last MAX_PUBLICATIONS versions that are within 7 days.
    // Always retain at least MAX_PUBLICATIONS regardless of age so cold boot
    // after a long offline period still has content to play.
    savePublication(deviceId, versionId, payload) {
        const all = this._read(this._pubFile);
        all.push({ deviceId, versionId, payload, savedAt: Date.now() });

        const mine = all.filter(p => p.deviceId === deviceId);
        const cutoff = Date.now() - SEVEN_DAYS_MS;
        const fresh = mine.filter(p => p.savedAt >= cutoff);
        const aged = mine.filter(p => p.savedAt < cutoff);
        const need = Math.max(0, MAX_PUBLICATIONS - fresh.length);
        const kept = [...aged.slice(-need), ...fresh].slice(-MAX_PUBLICATIONS);

        const others = all.filter(p => p.deviceId !== deviceId);
        this._write(this._pubFile, [...others, ...kept]);
    }

    getLatestPublication(deviceId) {
        const all = this._read(this._pubFile).filter(p => p.deviceId === deviceId);
        return all.length > 0 ? all[all.length - 1].payload : null;
    }

    getAllPublications(deviceId) {
        return this._read(this._pubFile)
            .filter(p => p.deviceId === deviceId)
            .map(p => p.payload);
    }

    saveSchedule(deviceId, payload) {
        const rest = this._read(this._scheduleFile).filter(x => x.deviceId !== deviceId);
        rest.push({ deviceId, payload, updatedAt: Date.now() });
        this._write(this._scheduleFile, rest);
    }

    getSchedule(deviceId) {
        const entry = this._read(this._scheduleFile).find(x => x.deviceId === deviceId);
        return entry?.payload ?? null;
    }

    saveDatasource(key, payload) {
        const rest = this._read(this._dsFile).filter(x => x.key !== key);
        rest.push({ key, payload, updatedAt: Date.now() });
        this._write(this._dsFile, rest);
    }

    getDatasource(key) {
        const entry = this._read(this._dsFile).find(x => x.key === key);
        return entry?.payload ?? null;
    }
}

module.exports = { SqliteStore, SEVEN_DAYS_MS, MAX_PUBLICATIONS };
