const fs = require('fs-extra');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const axios = require('axios');
const { logger } = require('./telemetry');

const PARTITION_A = 'app-a';
const PARTITION_B = 'app-b';
const ACTIVE_LINK = 'app-active';
const HEALTH_CHECK_TIMEOUT_MS = 60_000;
const HEALTH_CHECK_CONSECUTIVE_REQUIRED = 3;
const PARTITION_STATE_FILE = 'partition-state.json';

class ABPartition {
    constructor(baseDir) {
        this._baseDir = baseDir;
        this._partA = path.join(baseDir, PARTITION_A);
        this._partB = path.join(baseDir, PARTITION_B);
        this._activeLink = path.join(baseDir, ACTIVE_LINK);
        this._stateFile = path.join(baseDir, PARTITION_STATE_FILE);

        fs.ensureDirSync(this._partA);
        fs.ensureDirSync(this._partB);
    }

    async getState() {
        try {
            if (await fs.pathExists(this._stateFile)) {
                return (await fs.readJson(this._stateFile, { throws: false })) || {};
            }
        } catch {}
        return {};
    }

    async _saveState(state) {
        try {
            const current = await this.getState();
            await fs.writeJson(this._stateFile, {
                ...current,
                ...state,
                updatedAt: new Date().toISOString(),
            });
        } catch (e) {
            logger.error(`[A/B] Failed to save partition state: ${e.message}`);
        }
    }

    async getActivePartition() {
        const state = await this.getState();
        return state.activePartition || 'A';
    }

    async getInactivePartition() {
        return (await this.getActivePartition()) === 'A' ? 'B' : 'A';
    }

    getPartitionDir(partition) {
        return partition === 'A' ? this._partA : this._partB;
    }

    async getActiveDir() {
        return this.getPartitionDir(await this.getActivePartition());
    }

    async getInactiveDir() {
        return this.getPartitionDir(await this.getInactivePartition());
    }

    async installToInactive(packageFile, version, packageHash) {
        const targetDir = await this.getInactiveDir();
        const partition = await this.getInactivePartition();

        logger.info(`[A/B] Installing version ${version} to partition ${partition}`);

        // Verify hash before extraction (stream-based to avoid OOM on large firmware)
        const actualHash = await new Promise((resolve, reject) => {
            const hash = crypto.createHash('sha256');
            const stream = fs.createReadStream(packageFile);
            stream.on('data', (chunk) => hash.update(chunk));
            stream.on('error', reject);
            stream.on('end', () => resolve(hash.digest('hex')));
        });
        if (actualHash !== packageHash) {
            throw new Error(`Hash mismatch: expected ${packageHash}, got ${actualHash}`);
        }

        // Clean target partition
        await fs.emptyDir(targetDir);

        // Extract tarball to inactive partition (spawn avoids command injection)
        await new Promise((resolve, reject) => {
            const tar = spawn('tar', ['-xzf', packageFile, '-C', targetDir]);
            tar.on('close', (code) => {
                if (code === 0) resolve();
                else reject(new Error(`tar exited with code ${code}`));
            });
            tar.on('error', reject);
        });

        await this._saveState({
            [`partition${partition}Version`]: version,
            [`partition${partition}InstalledAt`]: new Date().toISOString(),
        });

        logger.info(`[A/B] Partition ${partition} installed with version ${version}`);
        return partition;
    }

    async atomicSwap() {
        const newActive = await this.getInactivePartition();
        const newActiveDir = this.getPartitionDir(newActive);
        const oldActive = await this.getActivePartition();

        // Atomic rename: create temp symlink, then rename over the old one
        const tempLink = this._activeLink + '.tmp';
        try {
            await fs.remove(tempLink).catch(() => {});
            await fs.symlink(newActiveDir, tempLink);
            await fs.rename(tempLink, this._activeLink);
        } catch (e) {
            // Fallback for platforms without atomic rename on symlinks
            await fs.remove(tempLink).catch(() => {});
            await fs.remove(this._activeLink).catch(() => {});
            await fs.symlink(newActiveDir, this._activeLink);
        }

        const state = await this.getState();
        await this._saveState({
            activePartition: newActive,
            backupPartition: oldActive,
            backupPartitionVersion: state[`partition${oldActive}Version`] || null,
            swappedAt: new Date().toISOString(),
            healthCheckPassed: false,
            healthCheckPending: true,
        });

        logger.info(`[A/B] Atomic swap: ${oldActive} → ${newActive}`);
        return { newActive, oldActive };
    }

    async rollback() {
        const current = await this.getActivePartition();
        const backup = current === 'A' ? 'B' : 'A';
        const backupDir = this.getPartitionDir(backup);

        logger.warn(`[A/B] Rolling back from partition ${current} to ${backup}`);

        const tempLink = this._activeLink + '.tmp';
        try {
            await fs.remove(tempLink).catch(() => {});
            await fs.symlink(backupDir, tempLink);
            await fs.rename(tempLink, this._activeLink);
        } catch (e) {
            await fs.remove(tempLink).catch(() => {});
            await fs.remove(this._activeLink).catch(() => {});
            await fs.symlink(backupDir, this._activeLink);
        }

        await this._saveState({
            activePartition: backup,
            rolledBackAt: new Date().toISOString(),
            rollbackReason: 'health-check-failed',
            healthCheckPending: false,
        });

        logger.warn(`[A/B] Rollback complete: now on partition ${backup}`);
        return backup;
    }

    async markHealthy() {
        await this._saveState({ healthCheckPassed: true, healthCheckPending: false });
        const active = await this.getActivePartition();
        logger.info(`[A/B] Health check passed — partition ${active} confirmed`);
    }

    async runHealthCheck(checks) {
        const { healthEndpoint, mqttConnected, playbackActive } = checks;
        const startTime = Date.now();
        const deadline = startTime + HEALTH_CHECK_TIMEOUT_MS;
        let consecutivePasses = 0;

        logger.info(`[A/B] Starting post-boot health check (requires ${HEALTH_CHECK_CONSECUTIVE_REQUIRED} consecutive passes)...`);

        while (Date.now() < deadline) {
            await new Promise(r => setTimeout(r, 5000));

            let healthy = true;

            if (healthEndpoint) {
                try {
                    const res = await axios.get(healthEndpoint, { timeout: 3000 });
                    if (res.status !== 200) healthy = false;
                } catch {
                    healthy = false;
                }
            }

            if (mqttConnected !== undefined && !mqttConnected()) {
                healthy = false;
            }

            if (playbackActive !== undefined && !playbackActive()) {
                healthy = false;
            }

            if (healthy) {
                consecutivePasses++;
                if (consecutivePasses >= HEALTH_CHECK_CONSECUTIVE_REQUIRED) {
                    await this.markHealthy();
                    return true;
                }
            } else {
                consecutivePasses = 0;
            }
        }

        logger.error(`[A/B] Health check failed after ${HEALTH_CHECK_TIMEOUT_MS}ms — triggering rollback`);
        return false;
    }
}

module.exports = {
    ABPartition,
    PARTITION_A,
    PARTITION_B,
    ACTIVE_LINK,
    HEALTH_CHECK_TIMEOUT_MS,
    HEALTH_CHECK_CONSECUTIVE_REQUIRED,
    PARTITION_STATE_FILE,
};
