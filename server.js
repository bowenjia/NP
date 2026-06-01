// Initialize OpenTelemetry
const { logger, setPlaylist, setSyncState } = require('./telemetry');

const express = require('express');
const axios = require('axios');
const os = require('os');
const fs = require('fs-extra');
const path = require('path');
const crypto = require('crypto');
const mqtt = require('mqtt');
const dgram = require('dgram');
const { generateCSR, saveCertificate } = require('./security');
const { matchesCron } = require('./cron-matcher');
const { selectStaleFiles, computeDiskUsagePct, shouldAlertDiskHigh } = require('./cache-helpers');
const { RAW_MAX_BYTES, isScreenshotTooLarge, buildScreenshotPayload } = require('./screenshot-helpers');
const { SqliteStore, SEVEN_DAYS_MS } = require('./sqlite-store');
const { ABPartition } = require('./ab-partition');
const { ManifestPuller } = require('./manifest-puller');

// Read version from package.json at startup; defaults to '1.0.0' if unavailable
let APP_VERSION = '1.0.0';
try {
    const pkg = JSON.parse(require('fs').readFileSync(require('path').join(__dirname, 'package.json'), 'utf8'));
    APP_VERSION = pkg.version || '1.0.0';
} catch (_e) {}

const app = express();
const PORT = process.env.PORT || 4000;
const CMS_URL = process.env.CMS_URL || 'http://web:3000';
const MQTT_URL = process.env.MQTT_BROKER_URL || 'mqtts://mqtt:8883';
let MQTT_USERNAME = process.env.MQTT_USERNAME || '';
let MQTT_PASSWORD = process.env.MQTT_PASSWORD || '';
let DEVICE_ID = process.env.DEVICE_ID;
let ORG_ID = process.env.ORG_ID; // Set from pairing response or env
const DEVICE_NAME = process.env.DEVICE_NAME || "Generic Device";
const PAIRING_CODE = process.env.PAIRING_CODE;
const PROVISION_KEY = process.env.PROVISION_KEY; // For ZTP

// ── HARDWARE FINGERPRINT ──
// Binds device identity to a STABLE per-device machine id that survives container
// recreation and reboots. MAC and hostname were previously hashed in, but both
// change every time a container is recreated (the veth MAC and the container-id
// hostname are fresh each time), so the server's anti-clone check rejected
// legitimate devices after every rebuild ("403 Hardware fingerprint mismatch").
// A random machine id, persisted in the cache volume, is stable for a given device
// yet still unique: a clone that copies only the PROVISION_KEY generates a fresh id,
// so its fingerprint mismatches the registered one and is still rejected.
function getHardwareFingerprint() {
    const idFile = path.join(__dirname, 'cache', 'machine-id');
    let machineId;
    try {
        machineId = fs.readFileSync(idFile, 'utf8').trim();
    } catch { /* not generated yet */ }
    if (!machineId) {
        machineId = crypto.randomBytes(32).toString('hex');
        try {
            fs.mkdirSync(path.dirname(idFile), { recursive: true });
            fs.writeFileSync(idFile, machineId, { mode: 0o600 });
        } catch (e) {
            console.error('[FINGERPRINT] Could not persist machine-id:', e.message);
        }
    }
    // Supplementary stable hardware bits (never the volatile MAC/hostname).
    const raw = [
        machineId,
        os.platform(),
        os.arch(),
        os.cpus()[0]?.model || 'unknown',
    ].join('|');
    return crypto.createHash('sha256').update(raw).digest('hex');
}

// Cache directory must be initialized before pairing code uses it
const CACHE_DIR = path.join(__dirname, 'cache');
const MEDIA_DIR = path.join(CACHE_DIR, 'media');
const STATE_FILE = path.join(CACHE_DIR, 'state.json');
fs.ensureDirSync(CACHE_DIR);
fs.ensureDirSync(MEDIA_DIR);
const store = new SqliteStore(CACHE_DIR);
// A/B partition dirs must live under a writable location. The daemon runs as a
// non-root user (security hardening); '/' (old parent-of-__dirname base) and the
// app root '/app' are root-owned, so mkdir there fails with EACCES. CACHE_DIR is
// the dir the Dockerfile chowns to the runtime user, so place partitions there.
// Override via AB_PARTITION_DIR if a dedicated volume is mounted.
const abPartition = new ABPartition(process.env.AB_PARTITION_DIR || path.join(CACHE_DIR, 'partitions'));
const manifestPuller = new ManifestPuller(CACHE_DIR, CMS_URL, () => getAuthHeaders());

function saveMqttCreds(username, password) {
    fs.writeFileSync(path.join(CACHE_DIR, 'mqtt-username'), username, { mode: 0o600 });
    fs.writeFileSync(path.join(CACHE_DIR, 'mqtt-password'), password, { mode: 0o600 });
    MQTT_USERNAME = username;
    MQTT_PASSWORD = password;
}

// Load persisted per-device MQTT credentials (written after ZTP / pairing)
const _mqttUFile = path.join(CACHE_DIR, 'mqtt-username');
const _mqttPFile = path.join(CACHE_DIR, 'mqtt-password');
if (fs.pathExistsSync(_mqttUFile) && fs.pathExistsSync(_mqttPFile)) {
    MQTT_USERNAME = fs.readFileSync(_mqttUFile, 'utf8').trim();
    MQTT_PASSWORD = fs.readFileSync(_mqttPFile, 'utf8').trim();
    logger.info('[AUTH] Loaded persisted per-device MQTT credentials.');
}

// ── ZERO-TOUCH PROVISIONING (ZTP) ──
async function attemptZTP() {
    if (!PROVISION_KEY || !DEVICE_ID) return false;

    for (let attempt = 1; attempt <= 60; attempt++) {
        // Nonce must be fresh each attempt (anti-replay window = ±5 min)
        const nonce = Date.now().toString();
        const hmac = crypto.createHmac('sha256', PROVISION_KEY).update(`${DEVICE_ID}:${nonce}`).digest('hex');
        try {
            const res = await axios.post(`${CMS_URL}/api/v1/devices/provision`, {
                deviceId: DEVICE_ID,
                nonce,
                hmac,
                hardwareFingerprint: getHardwareFingerprint(),
            }, { timeout: 10000 });
            const { apiToken, orgId: provisionedOrgId, mqttCredentials } = res.data;
            fs.writeFileSync(path.join(CACHE_DIR, 'api-token'), apiToken);
            if (provisionedOrgId) {
                ORG_ID = provisionedOrgId;
                fs.writeFileSync(path.join(CACHE_DIR, 'org-id'), provisionedOrgId);
            }
            if (mqttCredentials) {
                saveMqttCreds(mqttCredentials.username, mqttCredentials.password);
            }
            logger.info(`[ZTP] Zero-touch provisioning complete for ${DEVICE_ID}`);
            return true;
        } catch (e) {
            const status = e.response?.status;
            const msg = e.response?.data?.error || e.message;
            // 401 = wrong PROVISION_KEY — no point retrying
            if (status === 401) {
                logger.error(`[ZTP] HMAC verification failed — check PROVISION_KEY. Aborting ZTP.`);
                return false;
            }
            logger.info(`[ZTP] Attempt ${attempt}/60 failed (${status || 'network'}: ${msg}). Retrying in 10s...`);
            await new Promise(r => setTimeout(r, 10000));
        }
    }

    logger.error('[ZTP] Failed to provision after 60 attempts. Device will run without per-device MQTT credentials.');
    return false;
}

// ── AUTO-PAIRING VIA PAIRING CODE ──
async function attemptPairing() {
    if (DEVICE_ID) return; // Already have a device ID
    if (!PAIRING_CODE) {
        logger.error('[PAIRING] No DEVICE_ID or PAIRING_CODE set. Cannot start.');
        logger.info('[PAIRING] Set DEVICE_ID=<uuid> or PAIRING_CODE=<6-char> in environment.');
        process.exit(1);
    }

    logger.info(`[PAIRING] Attempting to pair with code: ${PAIRING_CODE.substring(0, 4)}****`);

    // Retry pairing until CMS is reachable (Docker startup ordering)
    for (let attempt = 1; attempt <= 60; attempt++) {
        try {
            const res = await axios.post(`${CMS_URL}/api/v1/devices/pair`, {
                pairingCode: PAIRING_CODE,
                hardwareFingerprint: getHardwareFingerprint(),
            }, { timeout: 5000 });

            DEVICE_ID = res.data.deviceId;
            ORG_ID = res.data.orgId || ORG_ID;
            logger.info(`[PAIRING] Success! Device ID: ${DEVICE_ID} (${res.data.deviceName}) Org: ${ORG_ID}`);

            // Persist the device ID so we don't need the pairing code again
            const idFile = path.join(CACHE_DIR, 'device-id');
            fs.writeFileSync(idFile, DEVICE_ID);
            if (ORG_ID) {
                fs.writeFileSync(path.join(CACHE_DIR, 'org-id'), ORG_ID);
            }
            // Persist the per-device Bearer token issued by the CMS on pairing.
            // This replaces the global DEVICE_SHARED_SECRET fallback — each device
            // now has its own scoped credential.
            if (res.data.apiToken) {
                fs.writeFileSync(path.join(CACHE_DIR, 'api-token'), res.data.apiToken);
                logger.info('[PAIRING] Per-device API token saved.');
            }
            if (res.data.mqttCredentials) {
                saveMqttCreds(res.data.mqttCredentials.username, res.data.mqttCredentials.password);
            }
            return;
        } catch (e) {
            const msg = e.response?.data?.error || e.message;
            if (e.response?.status === 404 || e.response?.status === 410) {
                // Invalid or expired pairing code — retry after delay instead of exiting
                logger.error(`[PAIRING] ${e.response.data?.error || 'Invalid/expired pairing code'}. Will retry in 60s...`);
                await new Promise(r => setTimeout(r, 60000));
                continue;
            }
            logger.info(`[PAIRING] Attempt ${attempt}/60 failed: ${msg}. Retrying in 10s...`);
            await new Promise(r => setTimeout(r, 10000));
        }
    }

    logger.error('[PAIRING] Failed to pair after 60 attempts. Exiting.');
    process.exit(1);
}

// Check for persisted device ID from previous pairing
if (!DEVICE_ID) {
    const idFile = path.join(CACHE_DIR, 'device-id');
    if (fs.pathExistsSync(idFile)) {
        DEVICE_ID = fs.readFileSync(idFile, 'utf8').trim();
        logger.info(`[PAIRING] Loaded persisted Device ID: ${DEVICE_ID}`);
    }
}

// Check for persisted org ID from previous pairing
if (!ORG_ID) {
    const orgIdFile = path.join(CACHE_DIR, 'org-id');
    if (fs.pathExistsSync(orgIdFile)) {
        ORG_ID = fs.readFileSync(orgIdFile, 'utf8').trim();
        logger.info(`[PAIRING] Loaded persisted Org ID: ${ORG_ID}`);
    }
}

// Load persisted per-device Bearer token (issued by CMS during ZTP or pairing).
// All outbound HTTP calls to the CMS use this for authentication — replacing the
// removed DEVICE_SHARED_SECRET global fallback.
let API_TOKEN = null;
const tokenFile = path.join(CACHE_DIR, 'api-token');
if (fs.pathExistsSync(tokenFile)) {
    API_TOKEN = fs.readFileSync(tokenFile, 'utf8').trim();
    logger.info('[AUTH] Loaded persisted per-device API token.');
}

/** Returns Authorization header object if we have a token, else empty object. */
function getAuthHeaders() {
    return API_TOKEN ? { Authorization: `Bearer ${API_TOKEN}` } : {};
}

// ── SYNC STATE (Industrial Standard) ──
const SYNC_ROLE = process.env.SYNC_ROLE || 'SLAVE';
const SYNC_GROUP = '239.0.0.1';
const SYNC_PORT = 5007;
const SYNC_MASTER_IP = process.env.SYNC_MASTER_IP || '';

let currentSyncData = {
    refTime: Date.now(),
    videoOffset: 0,
    sceneId: ''
};

// Initialize UDP Multicast Socket
const udpSocket = dgram.createSocket({ type: 'udp4', reuseAddr: true });

if (SYNC_ROLE === 'MASTER') {
    setInterval(() => {
        try {
            const payload = JSON.stringify({
                ...currentSyncData,
                refTime: Date.now() // Precise absolute reference time
            });
            udpSocket.send(payload, SYNC_PORT, SYNC_GROUP);
        } catch (e) {
            logger.error(`[SYNC] Master broadcast failed: ${e.message}`);
        }
    }, 500);
    logger.info(`[SYNC] MASTER initialized: Broadcasting pulses to ${SYNC_GROUP}:${SYNC_PORT}`);
} else {
    udpSocket.on('message', (msg, rinfo) => {
        if (SYNC_MASTER_IP && rinfo.address !== SYNC_MASTER_IP) {
            logger.warn(`[SYNC] Rejected packet from unauthorized sender ${rinfo.address} (expected ${SYNC_MASTER_IP})`);
            return;
        }
        try {
            const data = JSON.parse(msg.toString());
            currentSyncData = data;
        } catch (e) {}
    });

    udpSocket.bind(SYNC_PORT, () => {
        try {
            udpSocket.addMembership(SYNC_GROUP);
            logger.info(`[SYNC] SLAVE initialized: Listening on ${SYNC_GROUP}:${SYNC_PORT}`);
        } catch (e) {
            logger.error(`[SYNC] Failed to join multicast group: ${e.message}`);
        }
    });
}

// CACHE_DIR and STATE_FILE are defined at the top of the file (before pairing logic)

let downloadQueue = [];
let isDownloading = false;
let currentBatchTotal = 0;

// Declared here (before saveState/loadState) to avoid temporal dead zone — these
// variables are written by loadState() and must exist before it is called.
let currentPlaylistScenes = [];
let currentPlaylistId = null;
let activeSceneIds = [];

// ── PERSISTENCE HELPERS ──
const saveState = (playlist, status, playlistId) => {
    try {
        const existing = fs.pathExistsSync(STATE_FILE) ? fs.readJsonSync(STATE_FILE, { throws: false }) : {};
        fs.writeJsonSync(STATE_FILE, {
            ...existing,
            playlist,
            status,
            ...(playlistId !== undefined ? { playlistId } : {}),
            // Persist scene list so cold-start can play without waiting for CMS or MQTT
            ...(currentPlaylistScenes.length > 0 ? { scenes: currentPlaylistScenes } : {}),
        });
    } catch (e) {}
};

const loadState = () => {
    try {
        if (fs.pathExistsSync(STATE_FILE)) {
            const state = fs.readJsonSync(STATE_FILE);
            if (state.playlist) setPlaylist(state.playlist);
            if (state.status) setSyncState(state.status, state.status === 'SYNCED' ? 100 : 0);
            if (state.playlistId) currentPlaylistId = state.playlistId;
            // Restore persisted scenes for cold-start offline playback
            if (Array.isArray(state.scenes) && state.scenes.length > 0) {
                currentPlaylistScenes = state.scenes;
                logger.info(`[STARTUP] Loaded ${state.scenes.length} scenes from state.json (cold-start recovery)`);
            }
        }
    } catch (e) {}
};

// Fetch playlist scenes from CMS on startup so virtual playback survives daemon restarts.
// Called after API_TOKEN is confirmed — uses the device's own JWT for auth.
async function fetchPlaylistScenesOnStartup() {
    if (!API_TOKEN) return;
    try {
        const res = await axios.get(
            `${CMS_URL}/api/devices/${DEVICE_ID}/playlist`,
            { headers: getAuthHeaders(), timeout: 10_000 }
        );
        if (res.data?.scenes && Array.isArray(res.data.scenes) && res.data.scenes.length > 0) {
            // Restore playlistId from CMS (authoritative) rather than state file
            if (res.data.playlistId) currentPlaylistId = res.data.playlistId;
            currentPlaylistScenes = res.data.scenes;
            evaluateDayparting();
            startVirtualPlayback();
            logger.info(`[STARTUP] Recovered ${currentPlaylistScenes.length} scenes for playlist ${currentPlaylistId}`);
        } else {
            logger.info('[STARTUP] No active playlist with scenes — virtual playback waiting for MQTT publish', {});
        }
    } catch (e) {
        if (e.response?.status === 401) {
            handleAuthFailure().catch(() => {});
        }
        logger.warn('[STARTUP] Could not fetch playlist scenes from CMS — falling back to persisted scenes', {});
        // Try 7-day offline store before falling back to state.json scenes (P03)
        if (currentPlaylistScenes.length === 0) {
            const cached = store.getLatestPublication(DEVICE_ID);
            const scenes = cached?.scenes || cached?.layout?.scenes;
            if (Array.isArray(scenes) && scenes.length > 0) {
                currentPlaylistScenes = scenes;
                if (cached.playlistId) currentPlaylistId = cached.playlistId;
                logger.info(`[STARTUP] 7-day store recovery: ${currentPlaylistScenes.length} scenes from offline cache`);
            }
        }
        if (currentPlaylistScenes.length > 0) {
            evaluateDayparting();
            startVirtualPlayback();
            logger.info(`[STARTUP] Cold-start recovery: playing ${currentPlaylistScenes.length} persisted scenes`);
        }
    }
}

// Initialize from last known state before MQTT connects
loadState();

// ── DAYPARTING (Offline Time-Based Scene Filtering) ──
// currentPlaylistScenes, currentPlaylistId, activeSceneIds declared earlier (before saveState)

/**
 * Evaluate which scenes are active based on their scheduleCron fields.
 * Scenes without a cron are always eligible.
 * If every scene has a cron and none match, we fall back to showing all scenes
 * so the screen is never blank.
 */
function evaluateDayparting() {
    if (!currentPlaylistScenes || currentPlaylistScenes.length === 0) {
        activeSceneIds = [];
        return;
    }

    const now = new Date();
    const eligible = currentPlaylistScenes.filter(scene => {
        if (!scene.scheduleCron) return true; // no cron → always eligible
        return matchesCron(scene.scheduleCron, now);
    });

    // Fallback: never leave the screen blank
    if (eligible.length === 0) {
        activeSceneIds = currentPlaylistScenes.map(s => s.id);
        logger.info(`[DAYPART] No scenes matched cron at ${now.toISOString()} — falling back to all ${activeSceneIds.length} scenes`);
    } else {
        activeSceneIds = eligible.map(s => s.id);
        logger.info(`[DAYPART] ${eligible.length}/${currentPlaylistScenes.length} scenes active at ${now.toISOString()}`);
    }
}

// Re-evaluate every 60 seconds
setInterval(evaluateDayparting, 60_000);

// mqttClient is initialized in start() after DEVICE_ID is confirmed (pairing or env var).
// Initializing here would use DEVICE_ID=undefined for PAIRING_CODE scenarios, causing
// "signage/undefined/status" messages. All usages use mqttClient?.connected safe access.
let mqttClient = null;

function initMQTT() {
    const caPath = process.env.MQTT_CA_CERT;
    const caOpts = (caPath && fs.existsSync(caPath)) ? { ca: fs.readFileSync(caPath) } : {};
    mqttClient = mqtt.connect(MQTT_URL, {
        ...caOpts,
        clientId: `player-${DEVICE_ID}`,
        username: MQTT_USERNAME,
        password: MQTT_PASSWORD,
        clean: false,
        reconnectPeriod: 5000,
        keepalive: 30,
        will: { topic: `signage/${DEVICE_ID}/status`, payload: JSON.stringify({ status: 'OFFLINE', deviceId: DEVICE_ID }), qos: 1, retain: true }
    });

    mqttClient.on('connect', () => {
        logger.info(`MQTT Connected to ${MQTT_URL} | Device: ${DEVICE_ID} | Org: ${ORG_ID || 'unknown'}`);
        mqttClient.publish(`signage/${DEVICE_ID}/status`, JSON.stringify({ status: 'ONLINE', deviceId: DEVICE_ID }), { qos: 1, retain: true });

        // Drain any PoP events queued while MQTT was offline (#116)
        drainPopQueue().catch(() => {});

        // Subscribe to org-scoped topics (primary path — matches gateway publish format)
        if (ORG_ID) {
            mqttClient.subscribe(`org/${ORG_ID}/signage/${DEVICE_ID}/publish`);
            mqttClient.subscribe(`org/${ORG_ID}/signage/${DEVICE_ID}/command`);
            logger.info(`[MQTT] Subscribed to org-scoped topics: org/${ORG_ID}/signage/${DEVICE_ID}/*`);
        } else {
            logger.warn(`[MQTT] ORG_ID not set — skipping org-scoped topic subscription. Commands from CMS will not be received until device re-pairs.`);
        }

        // Subscribe to manifest-based publication_available events (Issue #189)
        if (ORG_ID) {
            mqttClient.subscribe(`org/${ORG_ID}/signage/${DEVICE_ID}/publication_available`);
        }

        // Keep legacy subscriptions for backward compatibility during transition
        mqttClient.subscribe(`signage/${DEVICE_ID}/publish`);
        mqttClient.subscribe(`signage/${DEVICE_ID}/command`);
        mqttClient.subscribe(`signage/broadcast/publish`);
    });

    mqttClient.on('message', (topic, message) => {
        try {
            const data = JSON.parse(message.toString());
            const payload = data.payload || data;

            const isCommandTopic = topic === `org/${ORG_ID}/signage/${DEVICE_ID}/command`
                || topic === `signage/${DEVICE_ID}/command`;

            if (isCommandTopic) {
                // Allowlist of valid actions — reject unknown commands before processing (#91)
                const ALLOWED_ACTIONS = ['ROTATE_CERT', 'REBOOT', 'RELOAD', 'SYNC', 'MUTE', 'UNMUTE', 'SCREENSHOT', 'UPDATE'];
                if (payload.action && !ALLOWED_ACTIONS.includes(payload.action)) {
                    logger.warn(`[SYSTEM] Rejected unknown command action "${payload.action}" — not in allowlist`);
                    return;
                }

                // Reject commands that have passed their expiry (guards against
                // stale queued messages delivered after a long offline period).
                if (payload.expiresAt && new Date(payload.expiresAt) < new Date()) {
                    logger.warn(`[SYSTEM] Received expired command "${payload.action}" (issued ${payload.issuedAt}), ignoring.`);
                    return;
                }

                if (payload.action === 'ROTATE_CERT') {
                    handleRotateCert();
                    return;
                }
                if (payload.action === 'REBOOT') {
                    logger.info(`[SYSTEM] Reboot command received (issued ${payload.issuedAt || 'unknown'})`);
                    const { exec: _exec } = require('child_process');
                    const _isContainer = require('fs').existsSync('/.dockerenv');
                    if (_isContainer) {
                        // In Docker: exit the process — the container restart policy handles the reboot
                        logger.info('[SYSTEM] Container mode — exiting process (Docker restart policy will restart)');
                        setTimeout(() => process.exit(0), 1000);
                    } else {
                        // Physical device: issue OS-level reboot
                        logger.info('[SYSTEM] Physical device — issuing OS reboot via systemctl');
                        _exec('sudo systemctl reboot 2>/dev/null || sudo reboot 2>/dev/null', (err) => {
                            if (err) {
                                logger.warn('[SYSTEM] OS reboot command failed, falling back to process exit');
                                setTimeout(() => process.exit(0), 1000);
                            }
                        });
                    }
                    return;
                }
                if (payload.action === 'RELOAD') {
                    logger.info(`[SYSTEM] Reload command received. Re-syncing content...`);
                    processQueue();
                    return;
                }
                if (payload.action === 'SYNC') {
                    logger.info(`[SYSTEM] Sync command received. Forcing sync...`);
                    processQueue();
                    return;
                }
                if (payload.action === 'MUTE') {
                    logger.info('[SYSTEM] Mute command received');
                    require('child_process').exec(
                        'amixer sset Master 0% --quiet 2>/dev/null || pactl set-sink-mute @DEFAULT_SINK@ 1 2>/dev/null || true',
                        (err) => { if (err) logger.warn('[SYSTEM] Mute: audio control unavailable (headless/container)'); }
                    );
                    return;
                }
                if (payload.action === 'UNMUTE') {
                    logger.info('[SYSTEM] Unmute command received');
                    require('child_process').exec(
                        'amixer sset Master 100% --quiet 2>/dev/null || pactl set-sink-mute @DEFAULT_SINK@ 0 2>/dev/null || true',
                        (err) => { if (err) logger.warn('[SYSTEM] Unmute: audio control unavailable (headless/container)'); }
                    );
                    return;
                }
                if (payload.action === 'SCREENSHOT') {
                    logger.info('[SYSTEM] Screenshot command received');
                    const { exec: _sx } = require('child_process');
                    const _screenshotPath = path.join(CACHE_DIR, 'screenshot.png');
                    _sx(
                        `DISPLAY=:0 scrot ${_screenshotPath} 2>/dev/null || DISPLAY=:0 import -window root ${_screenshotPath} 2>/dev/null`,
                        async (err) => {
                            if (err || !require('fs').existsSync(_screenshotPath)) {
                                logger.warn('[SYSTEM] Screenshot: no X11 display available (headless/container)');
                                await fs.remove(_screenshotPath).catch(() => {});
                                return;
                            }
                            try {
                                // Check file size before reading into memory to avoid OOM on large screenshots
                                const stat = await fs.stat(_screenshotPath);
                                if (isScreenshotTooLarge(stat.size)) {
                                    logger.warn(`[SYSTEM] Screenshot too large (${Math.round(stat.size / 1024)}KB raw > ${Math.round(RAW_MAX_BYTES / 1024)}KB limit) — skipping MQTT publish`);
                                    return;
                                }
                                const imgBuf = await fs.readFile(_screenshotPath);
                                if (mqttClient?.connected) {
                                    mqttClient.publish(
                                        `signage/${DEVICE_ID}/telemetry`,
                                        JSON.stringify(buildScreenshotPayload(imgBuf)),
                                        { qos: 1 },
                                    );
                                    logger.info('[SYSTEM] Screenshot uploaded via MQTT telemetry');
                                }
                            } catch (e) {
                                logger.error('[SYSTEM] Screenshot upload failed', e);
                            } finally {
                                // Always clean up temp file — don't accumulate on disk
                                await fs.remove(_screenshotPath).catch(() => {});
                            }
                        }
                    );
                    return;
                }
                if (payload.action === 'UPDATE') {
                    handleOtaUpdate(payload);
                    return;
                }
            }

            // Manifest-based pull: publication_available event (Issue #189)
            const isPubAvailable = topic === `org/${ORG_ID}/signage/${DEVICE_ID}/publication_available`;
            if (isPubAvailable && payload.commitSha) {
                manifestPuller.handlePublicationAvailable(payload.commitSha, DEVICE_ID, {
                    onProgress: (pct) => {
                        if (mqttClient?.connected) {
                            mqttClient.publish(`signage/${DEVICE_ID}/sync`, JSON.stringify({
                                status: 'DOWNLOADING', progress: pct,
                            }));
                        }
                        setSyncState('DOWNLOADING', pct);
                    },
                    onSuccess: (sha, manifest) => {
                        if (mqttClient?.connected) {
                            mqttClient.publish(`signage/${DEVICE_ID}/sync`, JSON.stringify({
                                status: 'SYNCED', progress: 100, commitSha: sha,
                            }));
                        }
                        setSyncState('SYNCED', 100);
                        saveState(manifest.playlistName || 'Active Playlist', 'SYNCED', manifest.playlistId);
                        if (manifest.scenes && Array.isArray(manifest.scenes)) {
                            currentPlaylistScenes = manifest.scenes;
                            currentPlaylistId = manifest.playlistId || currentPlaylistId;
                            evaluateDayparting();
                            startVirtualPlayback();
                        }
                    },
                    onError: (sha, err) => {
                        logger.error(`[MANIFEST] Failed to sync commit ${sha}: ${err.message}`);
                        if (mqttClient?.connected) {
                            mqttClient.publish(`signage/${DEVICE_ID}/sync`, JSON.stringify({
                                status: 'FAILED', error: err.message,
                            }));
                        }
                    },
                });
                return;
            }

            logger.info(`MQTT RX: ${topic} | Assets: ${payload.assets?.length || 0}`);

            const playlistName = payload.playlistName || payload.playlistId || "Active Playlist";

            if (payload.playlistId || payload.playlistName) {
                currentPlaylistId = payload.playlistId || null;
                setPlaylist(playlistName);
            }

            // ── Capture scene metadata for dayparting + virtual playback ──
            if (payload.scenes && Array.isArray(payload.scenes)) {
                currentPlaylistScenes = payload.scenes;
                evaluateDayparting();
                logger.info(`[DAYPART] Received ${currentPlaylistScenes.length} scenes from playlist`);
                startVirtualPlayback();
            } else if (payload.layout?.scenes && Array.isArray(payload.layout.scenes)) {
                currentPlaylistScenes = payload.layout.scenes;
                evaluateDayparting();
                logger.info(`[DAYPART] Received ${currentPlaylistScenes.length} scenes from layout`);
                startVirtualPlayback();
            }

            // Persist publication to 7-day offline store (P03)
            if (payload.playlistId || payload.scenes || payload.layout?.scenes) {
                store.savePublication(DEVICE_ID, payload.versionId || payload.playlistId || String(Date.now()), payload);
            }
            if (payload.schedule) {
                store.saveSchedule(DEVICE_ID, payload.schedule);
            }

            if (payload.assets) {
                addToDownloadQueue(payload.assets);
            } else {
                // No assets array at all? Treat as synced
                setSyncState('SYNCED', 100);
                saveState(playlistName, 'SYNCED', currentPlaylistId);
            }
        } catch (e) { logger.error("Parse Error", e); }
    });
}

const addToDownloadQueue = (assets) => {
    if (!assets || assets.length === 0) {
        // IoT Expert: No assets to download? Transition to SYNCED immediately.
        setSyncState('SYNCED', 100);
        const state = fs.readJsonSync(STATE_FILE, { throws: false });
        saveState(state?.playlist || "Active Playlist", 'SYNCED');
        if (mqttClient?.connected) {
            mqttClient.publish(`signage/${DEVICE_ID}/sync`, JSON.stringify({ status: 'SYNCED', progress: 100 }));
        }
        // Clear tracked paths and evict stale files — device was cleared of content.
        activeAssetPaths.clear();
        evictStaleCache().catch(() => {});
        return;
    }

    // Rebuild active asset paths so evictStaleCache() knows what to keep.
    // The hash MUST be computed from the same `fullUrl` that processQueue
    // uses when writing the file (~line 717), otherwise relative URLs
    // produce a different sha256 here and every cached file is treated as
    // stale on the next sync (#113 review CRITICAL).
    activeAssetPaths = new Set(assets.map(a => {
        const fullUrl = a.url.startsWith('http')
            ? a.url
            : `${CMS_URL}${a.url.startsWith('/') ? '' : '/'}${a.url}`;
        let ext = '.png';
        try { ext = path.extname(new URL(fullUrl).pathname) || '.png'; } catch (e) {}
        return `${getFileHash(fullUrl)}${ext}`;
    }));

    let added = 0;
    assets.forEach(a => {
        if (!downloadQueue.find(dq => dq.url === a.url)) {
            downloadQueue.push(a);
            added++;
        }
    });
    
    if (added > 0) {
        if (currentBatchTotal === 0) {
            currentBatchTotal = downloadQueue.length;
        } else {
            currentBatchTotal += added;
        }
    }
    processQueue();
};

const handleRotateCert = async () => {
    try {
        logger.info(`[SECURITY] Initiating certificate rotation for ${DEVICE_ID}`);
        const csr = generateCSR(DEVICE_ID);
        
        const response = await axios.post(`${CMS_URL}/api/v1/devices/issue-cert`, {
            deviceId: DEVICE_ID,
            csr: csr
        }, { headers: getAuthHeaders() });
        
        if (response.data.certificate) {
            saveCertificate(response.data.certificate);
            logger.info(`[SECURITY] Certificate rotation complete for ${DEVICE_ID}`);
            
            mqttClient.publish(`signage/${DEVICE_ID}/status`, JSON.stringify({
                status: 'ONLINE',
                deviceId: DEVICE_ID,
                certRotated: true,
                timestamp: new Date().toISOString()
            }));
        } else {
            throw new Error("No certificate returned from server");
        }
    } catch (error) {
        logger.error(`[SECURITY] Certificate rotation failed:`, error.message);
    }
};

// ── OTA UPDATE (#108) ──
// Handles MQTT UPDATE commands. Downloads the package, verifies SHA-256,
// extracts it over the current installation, then exits so Docker restarts with new code.
const OTA_TEMP_DIR = path.join(CACHE_DIR, 'ota-staging');

function validateOtaUrl(url) {
    let parsed;
    try { parsed = new URL(url); } catch { throw new Error('Invalid OTA URL'); }
    if (parsed.protocol !== 'https:') throw new Error('OTA URL must be https://');
    const blocked = /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)/;
    if (blocked.test(parsed.hostname)) throw new Error('OTA URL targets private network');
    return parsed;
}

async function reportUpdateStatus(status, progress, error) {
    if (mqttClient?.connected) {
        mqttClient.publish(`signage/${DEVICE_ID}/sync`, JSON.stringify({
            status: `OTA_${status}`, // OTA_DOWNLOADING, OTA_INSTALLING, OTA_FAILED, OTA_COMPLETE
            progress: progress ?? 0,
            ...(error ? { error } : {}),
        }), { qos: 1 });
    }
}

async function handleOtaUpdate(payload) {
    const { version, packageUrl, packageHash } = payload;
    if (!version || !packageUrl || !packageHash) {
        logger.warn('[OTA] Received UPDATE command with missing fields (version/packageUrl/packageHash) — ignoring');
        return;
    }

    if (version === APP_VERSION) {
        logger.info(`[OTA] Already at version ${version} — skipping update`);
        return;
    }

    const safeVersion = version.replace(/[^a-zA-Z0-9._-]/g, '_');

    logger.info(`[OTA] A/B partition update from ${APP_VERSION} → ${version}`);
    logger.info(`[OTA] Active partition: ${abPartition.getActivePartition()}, installing to: ${abPartition.getInactivePartition()}`);
    await reportUpdateStatus('DOWNLOADING', 0);

    const stagingDir = OTA_TEMP_DIR;
    const packageFile = path.join(stagingDir, `update-${safeVersion}.tar.gz`);

    try {
        validateOtaUrl(packageUrl);
    } catch (e) {
        logger.error(`[OTA] URL validation failed: ${e.message} — skipping update`);
        await reportUpdateStatus('FAILED', 0, e.message);
        return;
    }

    try {
        await fs.ensureDir(stagingDir);
        await fs.emptyDir(stagingDir);

        // Download package to staging
        const resp = await axios({ url: packageUrl, method: 'GET', responseType: 'stream', timeout: 120000 });
        const writer = fs.createWriteStream(packageFile);
        resp.data.pipe(writer);
        await new Promise((resolve, reject) => { writer.on('finish', resolve); writer.on('error', reject); });
        await reportUpdateStatus('DOWNLOADING', 50);

        // Install to inactive partition (includes SHA-256 verification)
        await reportUpdateStatus('INSTALLING', 70);
        await abPartition.installToInactive(packageFile, version, packageHash);
        logger.info(`[OTA] Package installed to partition ${abPartition.getInactivePartition()}`);

        // Atomic swap symlink
        const { newActive, oldActive } = await abPartition.atomicSwap();
        logger.info(`[OTA] Symlink swapped: ${oldActive} → ${newActive}. Starting health check...`);
        await reportUpdateStatus('INSTALLING', 90);

        // 60s health check
        const healthy = await abPartition.runHealthCheck({
            healthEndpoint: `http://localhost:${PORT}/health`,
            mqttConnected: () => mqttClient?.connected ?? false,
            playbackActive: () => currentPlaylistScenes.length > 0,
        });

        if (!healthy) {
            logger.error(`[OTA] Health check failed — rolling back to partition ${oldActive}`);
            await abPartition.rollback();
            await reportUpdateStatus('FAILED', 0, 'Health check failed — rolled back to previous version');
            await fs.remove(stagingDir).catch(() => {});
            // Restart to load old version
            setTimeout(() => process.exit(0), 2000);
            return;
        }

        logger.info(`[OTA] A/B update complete. Version ${version} active on partition ${newActive}`);
        await reportUpdateStatus('COMPLETE', 100);

        // Report partition state via telemetry
        if (mqttClient?.connected) {
            mqttClient.publish(`signage/${DEVICE_ID}/telemetry`, JSON.stringify({
                activePartition: newActive,
                backupPartition: oldActive,
                firmwareVersion: version,
                updateType: 'ab-partition',
            }), { qos: 1 });
        }

        // Clean up staging
        await fs.remove(stagingDir).catch(() => {});

        // Exit 0 — Docker restart policy will bring up the new code from new partition
        setTimeout(() => process.exit(0), 2000);
    } catch (e) {
        const errMsg = e instanceof Error ? e.message : String(e);
        logger.error(`[OTA] A/B update to ${version} failed: ${errMsg}`);
        await reportUpdateStatus('FAILED', 0, errMsg);
        await fs.remove(stagingDir).catch(() => {});
    }
}

const getFileHash = (url) => crypto.createHash('sha256').update(url).digest('hex');

// Files that must never be evicted from the cache directory
const PROTECTED_FILES = new Set([
    'state.json', 'api-token', 'device-id', 'org-id',
    'mqtt-username', 'mqtt-password', 'screenshot.png',
    'pop-queue.jsonl',      // PoP offline queue — must survive eviction and restarts (#116)
    'publications.json',    // 7-day publication cache (P03)
    'schedules.json',
    'datasources.json',
]);

// ── PoP OFFLINE QUEUE (#116) ──
// When MQTT is down, PoP events are written to pop-queue.jsonl (one JSON object per line).
// On MQTT reconnect the queue is drained and each event is published with QoS 1.
const POP_QUEUE_FILE = path.join(CACHE_DIR, 'pop-queue.jsonl');
const POP_QUEUE_MAX_EVENTS = 100_000; // LRU cap: drop oldest when exceeded

// OTel counter for dropped PoP events (P03 — 7-day offline guarantee)
const { meter } = require('./telemetry');
const popDropCounter = meter.createCounter('pop_queue_dropped_events', {
    description: 'PoP events dropped due to offline queue overflow (LRU)',
});

// In-memory event count avoids reading the full file on every append (O(1) fast path).
// Initialized lazily on first append; reset to 0 after drainPopQueue clears the file.
let _popQueueCount = null;

function _initPopQueueCount() {
    if (_popQueueCount !== null) return;
    _popQueueCount = fs.pathExistsSync(POP_QUEUE_FILE)
        ? fs.readFileSync(POP_QUEUE_FILE, 'utf8').split('\n').filter(Boolean).length
        : 0;
}

function appendPopQueue(payload) {
    try {
        _initPopQueueCount();
        if (_popQueueCount >= POP_QUEUE_MAX_EVENTS) {
            // LRU: read file once only when pruning is actually needed
            const lines = fs.readFileSync(POP_QUEUE_FILE, 'utf8').split('\n').filter(Boolean);
            const keep = Math.floor(POP_QUEUE_MAX_EVENTS / 2);
            const dropped = lines.length - keep;
            fs.writeFileSync(POP_QUEUE_FILE, lines.slice(-keep).join('\n') + '\n');
            _popQueueCount = keep;
            popDropCounter.add(dropped);
            logger.warn(`[POP] Offline queue hit ${POP_QUEUE_MAX_EVENTS} event cap — dropped ${dropped} oldest events`);
        }
        fs.appendFileSync(POP_QUEUE_FILE, JSON.stringify(payload) + '\n');
        _popQueueCount++;
    } catch (e) {
        logger.warn('[POP] Failed to write offline queue:', e.message);
    }
}

async function drainPopQueue() {
    if (!fs.pathExistsSync(POP_QUEUE_FILE)) return;
    let lines;
    try {
        lines = fs.readFileSync(POP_QUEUE_FILE, 'utf8').split('\n').filter(Boolean);
        if (lines.length === 0) return;
        // Clear file immediately — if MQTT publish fails below we re-queue below
        fs.writeFileSync(POP_QUEUE_FILE, '');
        _popQueueCount = 0;
    } catch (e) {
        logger.warn('[POP] Failed to read offline queue:', e.message);
        return;
    }

    let published = 0;
    const failed = [];
    for (const line of lines) {
        try {
            const event = JSON.parse(line);
            if (mqttClient?.connected) {
                mqttClient.publish(`signage/${DEVICE_ID}/pop`, JSON.stringify(event), { qos: 1 });
                published++;
            } else {
                failed.push(line);
            }
        } catch { failed.push(line); }
    }

    if (failed.length > 0) {
        // Re-queue events that could not be published
        fs.writeFileSync(POP_QUEUE_FILE, failed.join('\n') + '\n');
        _popQueueCount = failed.length;
    }
    if (published > 0) {
        logger.info(`[POP] Drained ${published} queued PoP event(s) after reconnect`);
    }
}

// Basenames of asset files belonging to the current playlist
let activeAssetPaths = new Set();

// Delete cached asset files not referenced by the current playlist (#111).
// Files newer than 7 days are preserved even if not in active playlist (P03).
async function evictStaleCache() {
    try {
        const files = await fs.readdir(MEDIA_DIR);
        const stale = selectStaleFiles({ files, activeAssetPaths, protectedFiles: PROTECTED_FILES });
        const cutoff = Date.now() - SEVEN_DAYS_MS;
        let evicted = 0;
        for (const file of stale) {
            const filePath = path.join(MEDIA_DIR, file);
            try {
                const stat = await fs.stat(filePath);
                if (stat.mtimeMs >= cutoff) continue; // keep files < 7 days old
                await fs.remove(filePath);
                evicted++;
            } catch {}
        }
        if (evicted > 0) logger.info(`[CACHE] Evicted ${evicted} stale asset(s) older than 7 days`);
    } catch (e) {
        logger.warn('[CACHE] Eviction scan failed', e.message);
    }
}

// Warn via MQTT if disk usage >80% (#111).
async function checkDiskUsage() {
    try {
        const stat = await fs.statfs(CACHE_DIR);
        const usedPct = computeDiskUsagePct(stat);
        if (shouldAlertDiskHigh(usedPct)) {
            logger.warn(`[DISK] Storage at ${usedPct.toFixed(1)}% — SD card may fill soon`);
            if (mqttClient?.connected) {
                mqttClient.publish(`signage/${DEVICE_ID}/telemetry`, JSON.stringify({
                    diskUsagePct: Math.round(usedPct), alert: 'DISK_HIGH',
                }), { qos: 1 });
            }
        }
    } catch (e) { /* statfs not available on all platforms */ }
}

// Re-authenticate when CMS returns 401 — re-run ZTP to refresh the token (#113).
let _reAuthInProgress = false;
async function handleAuthFailure() {
    if (_reAuthInProgress) return;
    _reAuthInProgress = true;
    logger.warn('[AUTH] 401 from CMS — re-authenticating via ZTP...');
    try {
        if (PROVISION_KEY) {
            const ok = await attemptZTP();
            if (ok) {
                // attemptZTP() writes the fresh token to disk but the in-memory
                // API_TOKEN constant is still the stale one. Without this reload
                // getAuthHeaders() keeps sending the old bearer → permanent 401
                // loop until restart (#113 review HIGH).
                try {
                    API_TOKEN = fs.readFileSync(tokenFile, 'utf8').trim();
                    logger.info('[AUTH] Re-ZTP succeeded — token refreshed in memory');
                } catch (e) {
                    logger.error('[AUTH] Re-ZTP wrote token but in-memory reload failed:', e.message);
                }
            } else {
                logger.error('[AUTH] Re-ZTP failed — manual re-provisioning required');
            }
        } else {
            logger.error('[AUTH] No PROVISION_KEY — cannot auto-refresh token');
        }
    } finally {
        _reAuthInProgress = false;
    }
}

const processQueue = async () => {
    if (isDownloading) return;
    if (downloadQueue.length === 0) {
        if (currentBatchTotal > 0) {
            if (mqttClient?.connected) {
                mqttClient.publish(`signage/${DEVICE_ID}/sync`, JSON.stringify({ status: 'SYNCED', progress: 100 }));
            }
            setSyncState('SYNCED', 100);
            const state = fs.readJsonSync(STATE_FILE, { throws: false });
            saveState(state?.playlist || "Active Playlist", 'SYNCED');
            currentBatchTotal = 0;
            evictStaleCache().catch(() => {});
            checkDiskUsage().catch(() => {});
        }
        return;
    }
    
    isDownloading = true;
    const asset = downloadQueue.shift();
    
    const completed = currentBatchTotal - (downloadQueue.length + 1);
    const progress = currentBatchTotal > 0 ? Math.round((completed / currentBatchTotal) * 100) : 0;
    
    if (mqttClient?.connected) {
        mqttClient.publish(`signage/${DEVICE_ID}/sync`, JSON.stringify({ status: 'DOWNLOADING', progress: Math.max(0, Math.min(99, progress)) }));
    }
    setSyncState('DOWNLOADING', progress);

    let fullUrl = asset.url;
    if (!fullUrl.startsWith('http')) {
        fullUrl = `${CMS_URL}${fullUrl.startsWith('/') ? '' : '/'}${fullUrl}`;
    }

    let ext = '.png';
    try {
        ext = path.extname(new URL(fullUrl).pathname) || '.png';
    } catch(e) {}
    
    const filePath = path.join(MEDIA_DIR, `${getFileHash(fullUrl)}${ext}`);

    try {
        if (!(await fs.pathExists(filePath))) {
            logger.info(`Fetching: ${fullUrl}`);
            const resp = await axios({ url: fullUrl, method: 'GET', responseType: 'stream', timeout: 30000 });
            // Write to a temp file first; rename atomically on success so a
            // mid-download crash never leaves a corrupt cached file.
            const tempPath = filePath + '.tmp';
            const writer = fs.createWriteStream(tempPath);
            resp.data.pipe(writer);
            await new Promise((res, rej) => { writer.on('finish', res); writer.on('error', rej); });

            // Verify SHA-256 hash before promoting temp → final to catch corrupt downloads (#107)
            if (asset.sha256) {
                const fileBuffer = await fs.readFile(tempPath);
                const actual = crypto.createHash('sha256').update(fileBuffer).digest('hex');
                if (actual !== asset.sha256) {
                    logger.error(`HASH MISMATCH: ${fullUrl} — expected ${asset.sha256} got ${actual} — discarding corrupt file`);
                    await fs.remove(tempPath).catch(() => {});
                    isDownloading = false;
                    setTimeout(processQueue, 500);
                    return;
                }
                logger.info(`HASH OK: ${filePath}`);
            }

            await fs.rename(tempPath, filePath);
            logger.info(`SUCCESS: ${filePath}`);
        } else {
            logger.info(`SKIP: ${fullUrl} (Cached)`);
        }
    } catch (e) {
        logger.error(`FAIL: ${fullUrl}`, e);
        await fs.remove(filePath + '.tmp').catch(() => {});
    }
    
    isDownloading = false;
    
    if (downloadQueue.length === 0) {
        if (mqttClient?.connected) {
            mqttClient.publish(`signage/${DEVICE_ID}/sync`, JSON.stringify({ status: 'SYNCED', progress: 100 }));
        }
        setSyncState('SYNCED', 100);
        const state = fs.readJsonSync(STATE_FILE, { throws: false });
        saveState(state?.playlist || "Active Playlist", 'SYNCED');
        currentBatchTotal = 0;
        evictStaleCache().catch(() => {});
        checkDiskUsage().catch(() => {});
    } else {
        setTimeout(processQueue, 500);
    }
};

app.use('/local-assets', express.static(MEDIA_DIR, { dotfiles: 'deny' }));
app.get('/health', (req, res) => res.json({ status: "ok", queue: downloadQueue.length }));

// ── LOCAL PLAYER SYNC ENDPOINTS ──
app.use(express.json());
app.use((req, res, next) => {
    const allowedOrigin = process.env.CMS_URL || 'http://localhost:3000';
    const requestOrigin = req.headers.origin;
    const corsOrigin = requestOrigin && requestOrigin === allowedOrigin ? requestOrigin : allowedOrigin;
    res.setHeader('Access-Control-Allow-Origin', corsOrigin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

app.post('/local/sync-pulse', (req, res) => {
    if (SYNC_ROLE === 'MASTER') {
        currentSyncData = {
            ...req.body,
            refTime: Date.now()
        };
    }
    res.sendStatus(200);
});

app.get('/local/sync-pulse', (req, res) => {
    res.json({
        ...currentSyncData,
        serverTime: Date.now() // Precise local server time for drift calc
    });
});

// ── DAYPARTING ENDPOINT — Browser player polls this to know which scenes to show ──
app.get('/local/active-scenes', (req, res) => {
    res.json({
        activeSceneIds,
        evaluatedAt: new Date().toISOString(),
        totalScenes: currentPlaylistScenes.length
    });
});

// ── VIRTUAL PLAYBACK LOOP (Proof of Play) ──
// Simulates the browser player's scene cycling so player daemons report PoP events
// even without a physical display. Each scene plays for its configured durationMs,
// then a PoP event is POST-ed to the CMS before advancing to the next scene.
let _virtualPlaybackTimer = null;
let _virtualSceneIndex = 0;

async function reportPoP(scene) {
    if (!currentPlaylistId) return;
    const mediaIds = (scene.zones || []).map(z => z.mediaId).filter(Boolean);
    if (mediaIds.length === 0) return;

    for (const mediaId of mediaIds) {
        const payload = JSON.stringify({
            playlistId: currentPlaylistId,
            mediaId,
            durationMs: scene.durationMs ?? 5000,
            playedAt: new Date().toISOString(),
        });

        const popEvent = JSON.parse(payload);

        if (mqttClient?.connected) {
            // Primary: MQTT with QoS 1 — broker guarantees at-least-once delivery
            mqttClient.publish(`signage/${DEVICE_ID}/pop`, payload, { qos: 1 });
        } else if (API_TOKEN) {
            // Secondary: HTTP direct POST if MQTT is down but network is up
            let httpOk = false;
            try {
                await axios.post(
                    `${CMS_URL}/api/devices/${DEVICE_ID}/pop`,
                    popEvent,
                    { headers: getAuthHeaders(), timeout: 5000 }
                );
                httpOk = true;
            } catch { /* fall through to offline queue */ }

            // Tertiary: write to offline queue — drained on next MQTT reconnect (#116)
            if (!httpOk) {
                appendPopQueue(popEvent);
            }
        } else {
            // No credentials available — queue for later delivery
            appendPopQueue(popEvent);
        }
    }
}

function startVirtualPlayback() {
    if (_virtualPlaybackTimer) clearTimeout(_virtualPlaybackTimer);
    _virtualSceneIndex = 0;
    scheduleNextVirtualScene();
}

function scheduleNextVirtualScene() {
    // Honour daypart filter; fall back to full list if none are eligible
    const pool = activeSceneIds.length > 0
        ? currentPlaylistScenes.filter(s => activeSceneIds.includes(s.id))
        : currentPlaylistScenes;

    if (pool.length === 0 || !currentPlaylistId) {
        // No playable scenes — retry after 30s
        _virtualPlaybackTimer = setTimeout(scheduleNextVirtualScene, 30_000);
        return;
    }

    _virtualSceneIndex = _virtualSceneIndex % pool.length;
    const scene = pool[_virtualSceneIndex];
    const durationMs = Math.max(1000, scene.durationMs ?? 5000);

    _virtualPlaybackTimer = setTimeout(async () => {
        await reportPoP(scene);
        _virtualSceneIndex = (_virtualSceneIndex + 1) % pool.length;
        scheduleNextVirtualScene();
    }, durationMs);
}

// ── REAL-TIME CMS SYNC (Ticket 29.1 Fix) ──
const TELEMETRY_INTERVAL_MS = Math.max(5000, parseInt(process.env.TELEMETRY_INTERVAL_MS || '10000', 10));
// Add up to 20% random jitter to prevent thundering-herd on fleet restart
const telemetryJitter = () => Math.floor(Math.random() * TELEMETRY_INTERVAL_MS * 0.2);

// Per-process CPU baseline for MQTT telemetry (separate tracker from OTel)
let _mqttPrevCpu = process.cpuUsage();
let _mqttPrevTime = Date.now();

function scheduleTelemetry() {
    setTimeout(async () => {
        // The re-arm (recursive scheduleTelemetry) MUST run even if the body throws.
        // A single uncaught exception here used to skip the re-arm and permanently kill
        // periodic telemetry for the lifetime of the process — the device then looked
        // OFFLINE in the CMS forever (last_seen never advanced) despite a live MQTT link.
        try {
            if (mqttClient?.connected) {
                // Per-process CPU: same delta approach as OTel telemetry.js
                const nowMs = Date.now();
                const elapsedUs = (nowMs - _mqttPrevTime) * 1000;
                const cpuDelta = process.cpuUsage(_mqttPrevCpu);
                const cpuPercent = elapsedUs > 0
                    ? Math.min(((cpuDelta.user + cpuDelta.system) / elapsedUs) * 100, 100)
                    : 0;
                _mqttPrevCpu = process.cpuUsage();
                _mqttPrevTime = nowMs;
                const ramUsageMb = Math.round(process.memoryUsage().rss / 1024 / 1024);

                mqttClient.publish(`signage/${DEVICE_ID}/telemetry`, JSON.stringify({
                    cpu: cpuPercent,
                    ram: ramUsageMb,
                    ip: getLocalIP(),
                    uptime: process.uptime(),
                    fingerprint: getHardwareFingerprint(),
                    playlistId: currentPlaylistId,
                    appVersion: APP_VERSION,
                }));
            } else {
                logger.warn('[TELEMETRY] skipped publish — MQTT client not connected');
            }
        } catch (err) {
            logger.error('[TELEMETRY] publish failed', { error: err?.message || String(err) });
        } finally {
            scheduleTelemetry();
        }
    }, TELEMETRY_INTERVAL_MS + telemetryJitter());
}
scheduleTelemetry();

function getLocalIP() {
    const nets = os.networkInterfaces();
    for (const name of Object.keys(nets)) {
        for (const net of nets[name]) {
            if (net.family === 'IPv4' && !net.internal) return net.address;
        }
    }
    return '127.0.0.1';
}

// ── LOCAL ENDPOINT SECURITY ──
// Restrict sync-pulse and active-scenes to localhost only
app.use(['/local/sync-pulse', '/local/active-scenes'], (req, res, next) => {
    const clientIp = req.ip || req.connection?.remoteAddress || '';
    if (!clientIp.includes('127.0.0.1') && !clientIp.includes('::1') && clientIp !== '::ffff:127.0.0.1') {
        return res.status(403).json({ error: 'Local access only' });
    }
    next();
});

// ── STARTUP ──
async function start() {
    // ZTP: attempt zero-touch provisioning if PROVISION_KEY is set
    if (PROVISION_KEY && DEVICE_ID) {
        await attemptZTP();
    }
    await attemptPairing(); // No-op if DEVICE_ID already set
    // Verify local manifest integrity on startup (Issue #189)
    const manifestCheck = await manifestPuller.verifyLocalFiles();
    if (manifestCheck.valid) {
        logger.info(`[STARTUP] Manifest verified — active commit: ${manifestCheck.commitSha}`);
    } else {
        logger.info(`[STARTUP] Manifest verification: ${manifestCheck.reason} — will sync on next publication_available`);
    }
    // Restore playlist scenes from CMS before MQTT connects so virtual playback
    // starts immediately on restart without waiting for the next MQTT publish.
    await fetchPlaylistScenesOnStartup();
    // Initialize MQTT only after DEVICE_ID is confirmed — prevents signage/undefined/* topics
    initMQTT();
    app.listen(PORT, '0.0.0.0', () => console.log(`[DAEMON] Running on ${PORT} | Device: ${DEVICE_ID}`));
}
start();
