const crypto = require('crypto');
const fs = require('fs-extra');
const path = require('path');
const { execFileSync } = require('child_process');

const SECRETS_DIR = path.join(__dirname, 'secrets');
fs.ensureDirSync(SECRETS_DIR);

const PRIVATE_KEY_PATH = path.join(SECRETS_DIR, 'device.key');
const CSR_PATH = path.join(SECRETS_DIR, 'device.csr');
const CERT_PATH = path.join(SECRETS_DIR, 'device.crt');

/**
 * Generates a CSR (Certificate Signing Request) for the player device.
 * Uses node:crypto for key generation and openssl for CSR generation.
 * @param {string} deviceId The ID of the device.
 * @returns {string} The PEM-encoded CSR.
 */
function generateCSR(deviceId) {
    console.log(`[SECURITY] Generating CSR for device: ${deviceId}`);
    
    // 1. Generate Private Key if it doesn't exist
    if (!fs.existsSync(PRIVATE_KEY_PATH)) {
        console.log(`[SECURITY] Generating new RSA 2048 private key...`);
        const { privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        });
        fs.writeFileSync(PRIVATE_KEY_PATH, privateKey, { mode: 0o600 });
    }

    // 2. Generate CSR using openssl
    // Using openssl command since node:crypto doesn't support CSR generation natively
    // execFileSync does not invoke a shell — no shell injection risk
    const subj = `/CN=${deviceId}`;
    try {
        execFileSync('openssl', ['req', '-new', '-key', PRIVATE_KEY_PATH, '-out', CSR_PATH, '-subj', subj]);
        console.log(`[SECURITY] CSR generated successfully at ${CSR_PATH}`);
        return fs.readFileSync(CSR_PATH, 'utf8');
    } catch (error) {
        console.error(`[SECURITY] Failed to generate CSR:`, error.message);
        throw error;
    }
}

/**
 * Saves the signed certificate from the server.
 * @param {string} certificate The PEM-encoded certificate.
 */
function saveCertificate(certificate) {
    fs.writeFileSync(CERT_PATH, certificate);
    console.log(`[SECURITY] Certificate saved to ${CERT_PATH}`);
}

function getCertRemainingDays() {
    if (!fs.existsSync(CERT_PATH)) return -1;
    try {
        const out = execFileSync('openssl', ['x509', '-in', CERT_PATH, '-noout', '-enddate']).toString();
        const endDateStr = out.replace('notAfter=', '').trim();
        return Math.floor((new Date(endDateStr).getTime() - Date.now()) / (1000 * 60 * 60 * 24));
    } catch {
        return -1;
    }
}

async function autoRenewCert(deviceId, cmsBaseUrl, bearerToken) {
    const remaining = getCertRemainingDays();
    if (remaining < 0 || remaining > 30) return false;

    console.log(`[SECURITY] Cert expires in ${remaining} days — initiating renewal`);

    try {
        const csr = generateCSR(deviceId);
        const res = await fetch(`${cmsBaseUrl}/api/v1/devices/issue-cert`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${bearerToken}`,
            },
            body: JSON.stringify({ deviceId, csr }),
        });

        if (!res.ok) {
            const err = await res.text();
            throw new Error(`CMS returned ${res.status}: ${err}`);
        }

        const { certificate } = await res.json();
        saveCertificate(certificate);
        console.log(`[SECURITY] Certificate renewed successfully`);
        return true;
    } catch (e) {
        console.error(`[SECURITY] Certificate renewal failed:`, e.message);
        if (remaining <= 7) {
            console.error(JSON.stringify({
                severity: 'CRITICAL',
                event: 'cert_renewal_failed',
                deviceId,
                remainingDays: remaining,
                error: e.message,
            }));
        }
        return false;
    }
}

function startCertMonitor(deviceId, cmsBaseUrl, bearerToken, intervalMs = 24 * 60 * 60 * 1000) {
    const check = () => autoRenewCert(deviceId, cmsBaseUrl, bearerToken);
    check();
    return setInterval(check, intervalMs);
}

module.exports = {
    generateCSR,
    saveCertificate,
    getCertRemainingDays,
    autoRenewCert,
    startCertMonitor,
    PRIVATE_KEY_PATH,
    CERT_PATH,
    CSR_PATH,
};
