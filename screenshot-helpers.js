/**
 * Pure helpers for player-daemon SCREENSHOT command (#110).
 *
 * Extracted from server.js so the size guard + cleanup decision logic
 * can be exercised by unit tests without invoking scrot, MQTT, or fs.
 */

const SCREENSHOT_MAX_B64_CHARS = 1 * 1024 * 1024; // 1 MB base64 limit

/**
 * Maximum raw PNG byte size that, after base64-encoding, will still fit
 * under SCREENSHOT_MAX_B64_CHARS. Base64 inflates by ~33% (4 chars per
 * 3 bytes), so the raw cap is ceil(limit * 0.75).
 */
const RAW_MAX_BYTES = Math.ceil(SCREENSHOT_MAX_B64_CHARS * 0.75);

/**
 * Whether a captured screenshot is too large to publish over MQTT.
 *
 * @param {number} byteSize Raw PNG byte size as reported by fs.stat()
 * @param {number} [rawLimit=RAW_MAX_BYTES] Override for tests
 * @returns {boolean}
 */
function isScreenshotTooLarge(byteSize, rawLimit = RAW_MAX_BYTES) {
    if (typeof byteSize !== 'number' || !Number.isFinite(byteSize) || byteSize < 0) return true;
    return byteSize > rawLimit;
}

/**
 * Build the MQTT telemetry payload for a screenshot upload.
 *
 * @param {Buffer|string} imgBuf  Image bytes (Buffer) or pre-encoded base64 string
 * @param {Date}          [when=new Date()] Capture timestamp
 * @returns {{screenshot: string, screenshotAt: string}}
 */
function buildScreenshotPayload(imgBuf, when = new Date()) {
    const base64 =
        Buffer.isBuffer(imgBuf) ? imgBuf.toString('base64')
            : typeof imgBuf === 'string' ? imgBuf
                : '';
    return {
        screenshot: `data:image/png;base64,${base64}`,
        screenshotAt: when.toISOString(),
    };
}

module.exports = {
    SCREENSHOT_MAX_B64_CHARS,
    RAW_MAX_BYTES,
    isScreenshotTooLarge,
    buildScreenshotPayload,
};
