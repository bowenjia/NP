const fs = require('fs-extra');
const path = require('path');
const crypto = require('crypto');
const axios = require('axios');
const { logger } = require('./telemetry');

const MANIFEST_FILE = 'manifest.json';
const ACTIVE_COMMIT_FILE = 'active-commit.json';

class ManifestPuller {
    constructor(cacheDir, cmsUrl, getAuthHeaders) {
        this._cacheDir = cacheDir;
        this._cmsUrl = cmsUrl;
        this._getAuthHeaders = getAuthHeaders;
        this._manifestFile = path.join(cacheDir, MANIFEST_FILE);
        this._commitFile = path.join(cacheDir, ACTIVE_COMMIT_FILE);
    }

    _safePath(localName) {
        const resolved = path.resolve(this._cacheDir, localName);
        if (!resolved.startsWith(path.resolve(this._cacheDir) + path.sep)) {
            throw new Error(`Path traversal detected: ${localName}`);
        }
        return resolved;
    }

    getActiveCommit() {
        try {
            if (fs.pathExistsSync(this._commitFile)) {
                return fs.readJsonSync(this._commitFile, { throws: false });
            }
        } catch {}
        return null;
    }

    _saveActiveCommit(commitSha, manifest) {
        fs.writeJsonSync(this._commitFile, {
            commitSha,
            activatedAt: new Date().toISOString(),
            fileCount: manifest.files?.length ?? 0,
        });
        fs.writeJsonSync(this._manifestFile, manifest);
    }

    async verifyLocalFiles() {
        const commit = this.getActiveCommit();
        if (!commit) {
            logger.info('[MANIFEST] No active commit — fresh device');
            return { valid: false, reason: 'no-commit' };
        }

        let manifest;
        try {
            manifest = fs.readJsonSync(this._manifestFile, { throws: false });
        } catch {
            return { valid: false, reason: 'no-manifest' };
        }

        if (!manifest?.files || !Array.isArray(manifest.files)) {
            return { valid: false, reason: 'invalid-manifest' };
        }

        for (const file of manifest.files) {
            let filePath;
            try {
                filePath = this._safePath(file.localName);
            } catch (e) {
                logger.warn(`[MANIFEST] ${e.message} — skipping file`);
                continue;
            }
            if (!fs.pathExistsSync(filePath)) {
                logger.warn(`[MANIFEST] Missing file: ${file.localName}`);
                return { valid: false, reason: 'missing-file', file: file.localName };
            }

            if (file.sha256) {
                const actual = await new Promise((resolve, reject) => {
                    const hash = crypto.createHash('sha256');
                    const stream = fs.createReadStream(filePath);
                    stream.on('data', (chunk) => hash.update(chunk));
                    stream.on('error', reject);
                    stream.on('end', () => resolve(hash.digest('hex')));
                });
                if (actual !== file.sha256) {
                    logger.warn(`[MANIFEST] Hash mismatch: ${file.localName}`);
                    return { valid: false, reason: 'hash-mismatch', file: file.localName };
                }
            }
        }

        logger.info(`[MANIFEST] Local files verified OK for commit ${commit.commitSha}`);
        return { valid: true, commitSha: commit.commitSha };
    }

    async pullManifest(commitSha, deviceId) {
        const url = `${this._cmsUrl}/api/v1/publications/${commitSha}/manifest`;
        try {
            const res = await axios.get(url, {
                headers: this._getAuthHeaders(),
                timeout: 15000,
            });
            return res.data;
        } catch (e) {
            logger.error(`[MANIFEST] Failed to pull manifest for ${commitSha}: ${e.message}`);
            throw e;
        }
    }

    async incrementalSync(manifest, onProgress) {
        const files = manifest.files || [];
        const toDownload = [];

        for (const file of files) {
            let localPath;
            try {
                localPath = this._safePath(file.localName);
            } catch (e) {
                logger.warn(`[MANIFEST] ${e.message} — skipping file`);
                continue;
            }
            if (fs.pathExistsSync(localPath) && file.sha256) {
                const actual = await new Promise((resolve, reject) => {
                    const hash = crypto.createHash('sha256');
                    const stream = fs.createReadStream(localPath);
                    stream.on('data', (chunk) => hash.update(chunk));
                    stream.on('error', reject);
                    stream.on('end', () => resolve(hash.digest('hex')));
                });
                if (actual === file.sha256) continue;
            }
            toDownload.push(file);
        }

        logger.info(`[MANIFEST] Incremental sync: ${toDownload.length}/${files.length} files to download`);

        for (let i = 0; i < toDownload.length; i++) {
            const file = toDownload[i];
            let localPath;
            try {
                localPath = this._safePath(file.localName);
            } catch (e) {
                logger.warn(`[MANIFEST] ${e.message} — skipping file`);
                continue;
            }
            const tempPath = localPath + '.tmp';

            try {
                const fullUrl = file.url.startsWith('http')
                    ? file.url
                    : `${this._cmsUrl}${file.url.startsWith('/') ? '' : '/'}${file.url}`;

                const resp = await axios({
                    url: fullUrl,
                    method: 'GET',
                    responseType: 'stream',
                    headers: this._getAuthHeaders(),
                    timeout: 60000,
                });
                const writer = fs.createWriteStream(tempPath);
                resp.data.pipe(writer);
                await new Promise((resolve, reject) => {
                    writer.on('finish', resolve);
                    writer.on('error', reject);
                    resp.data.on('error', reject);
                });

                if (file.sha256) {
                    const actual = await new Promise((resolve, reject) => {
                        const hash = crypto.createHash('sha256');
                        const stream = fs.createReadStream(tempPath);
                        stream.on('data', (chunk) => hash.update(chunk));
                        stream.on('error', reject);
                        stream.on('end', () => resolve(hash.digest('hex')));
                    });
                    if (actual !== file.sha256) {
                        logger.error(`[MANIFEST] Hash mismatch after download: ${file.localName}`);
                        await fs.remove(tempPath).catch(() => {});
                        throw new Error(`Hash mismatch: ${file.localName}`);
                    }
                }

                await fs.rename(tempPath, localPath);
                logger.info(`[MANIFEST] Downloaded: ${file.localName}`);
            } catch (e) {
                await fs.remove(tempPath).catch(() => {});
                throw e;
            }

            if (onProgress) {
                onProgress(Math.round(((i + 1) / toDownload.length) * 100));
            }
        }

        return { downloaded: toDownload.length, total: files.length };
    }

    async handlePublicationAvailable(commitSha, deviceId, callbacks) {
        const { onProgress, onSuccess, onError } = callbacks;
        const activeCommit = this.getActiveCommit();

        if (activeCommit?.commitSha === commitSha) {
            logger.info(`[MANIFEST] Already at commit ${commitSha} — skipping`);
            return;
        }

        try {
            const manifest = await this.pullManifest(commitSha, deviceId);
            await this.incrementalSync(manifest, onProgress);
            this._saveActiveCommit(commitSha, manifest);
            logger.info(`[MANIFEST] Atomic swap to commit ${commitSha} complete`);
            if (onSuccess) onSuccess(commitSha, manifest);
        } catch (e) {
            logger.error(`[MANIFEST] Pull failed for ${commitSha} — keeping old active`);
            if (onError) onError(commitSha, e);
        }
    }
}

module.exports = { ManifestPuller, MANIFEST_FILE, ACTIVE_COMMIT_FILE };
