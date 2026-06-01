const { NodeSDK } = require('@opentelemetry/sdk-node');
const { OTLPMetricExporter } = require('@opentelemetry/exporter-metrics-otlp-proto');
const { PeriodicExportingMetricReader } = require('@opentelemetry/sdk-metrics');
const { OTLPLogExporter } = require('@opentelemetry/exporter-logs-otlp-proto');
const { BatchLogRecordProcessor } = require('@opentelemetry/sdk-logs');
const { logs } = require('@opentelemetry/api-logs');
const { resourceFromAttributes } = require('@opentelemetry/resources');
const { ATTR_SERVICE_NAME } = require('@opentelemetry/semantic-conventions');
const os = require('os');
const fs = require('fs');
const axios = require('axios');
const { metrics } = require('@opentelemetry/api');

const DEVICE_ID = process.env.DEVICE_ID || 'unknown-device';
const DEVICE_NAME = process.env.DEVICE_NAME || 'Unknown Device';
const OTEL_ENDPOINT = process.env.OTEL_EXPORTER_OTLP_ENDPOINT || 'http://host.docker.internal:4318';

const resource = resourceFromAttributes({
    [ATTR_SERVICE_NAME]: 'player-daemon',
    'device.id': DEVICE_ID,
    'device.name': DEVICE_NAME,
    'device.os': os.platform(),
});

// Initialize OpenTelemetry SDK
const sdk = new NodeSDK({
    resource,
    metricReader: new PeriodicExportingMetricReader({
        exporter: new OTLPMetricExporter({ url: `${OTEL_ENDPOINT}/v1/metrics` }),
        exportIntervalMillis: 15000,
    }),
    logRecordProcessor: new BatchLogRecordProcessor(
        new OTLPLogExporter({ url: `${OTEL_ENDPOINT}/v1/logs` })
    )
});

sdk.start();

const otelLogger = logs.getLogger('np-logger');

const logger = {
    info: (msg, meta = {}) => {
        console.log(`[INFO] ${msg}`, JSON.stringify(meta));
        try {
            otelLogger.emit({
                severityNumber: 9,
                severityText: 'INFO',
                body: msg,
                attributes: { ...meta, job: 'player-daemon', device_id: DEVICE_ID }
            });
        } catch (e) {}
    },
    warn: (msg, meta = {}) => {
        console.warn(`[WARN] ${msg}`, JSON.stringify(meta));
        try {
            otelLogger.emit({
                severityNumber: 13,
                severityText: 'WARN',
                body: msg,
                attributes: { ...meta, job: 'player-daemon', device_id: DEVICE_ID }
            });
        } catch (e) {}
    },
    error: (msg, err = {}) => {
        console.error(`[ERROR] ${msg}`, err);
        try {
            otelLogger.emit({
                severityNumber: 17,
                severityText: 'ERROR',
                body: msg,
                attributes: { error_msg: err.message || String(err), job: 'player-daemon', device_id: DEVICE_ID }
            });
        } catch (e) {}
    }
};

let currentPlaylist = 'None';
let localIp = '127.0.0.1';

function getLocalIP() {
    const nets = os.networkInterfaces();
    for (const name of Object.keys(nets)) {
        for (const net of nets[name]) {
            if (net.family === 'IPv4' && !net.internal) return net.address;
        }
    }
    return '127.0.0.1';
}

localIp = getLocalIP();

const meter = metrics.getMeter('np-meter');
const cpuGauge = meter.createObservableGauge('device_cpu_usage', { unit: 'percent' });
const memoryGauge = meter.createObservableGauge('device_memory_usage', { unit: 'bytes' });
const networkRttGauge = meter.createObservableGauge('device_network_rtt', { unit: 'milliseconds' });
const syncProgressGauge = meter.createObservableGauge('device_sync_progress', { unit: 'percent' });
const storageUsageGauge = meter.createObservableGauge('device_storage_usage', { unit: 'bytes' });
const uptimeGauge = meter.createObservableGauge('device_uptime', { unit: 'seconds' });
const infoGauge = meter.createObservableGauge('device_info');

let currentSyncProgress = 100;
let lastSyncTimestamp = Date.now();

// Baseline for per-process CPU delta calculation
let prevCpuUsage = process.cpuUsage();
let prevCpuTime = Date.now();

meter.addBatchObservableCallback((observableResult) => {
    // Per-process CPU: delta of user+sys microseconds over elapsed wall-clock microseconds.
    // Unlike os.cpus() / os.loadavg(), this reflects only THIS container's process.
    const now = Date.now();
    const elapsedUs = (now - prevCpuTime) * 1000; // ms → μs
    const usage = process.cpuUsage(prevCpuUsage);
    const cpuPercent = elapsedUs > 0
        ? Math.min(((usage.user + usage.system) / elapsedUs) * 100, 100)
        : 0;
    prevCpuUsage = process.cpuUsage();
    prevCpuTime = now;

    // Per-process RSS: actual physical memory used by this container's process.
    // os.totalmem() - os.freemem() is host-level and identical across all containers.
    const memBytes = process.memoryUsage().rss;

    observableResult.observe(cpuGauge, cpuPercent);
    observableResult.observe(memoryGauge, memBytes);
    observableResult.observe(uptimeGauge, process.uptime()); // process uptime, not host
    observableResult.observe(syncProgressGauge, currentSyncProgress);
    
    const start = Date.now();
    axios.get(`${OTEL_ENDPOINT.replace(':4318', ':4000')}/health`).then(() => {
        global.lastRtt = Date.now() - start;
    }).catch(() => {});
    observableResult.observe(networkRttGauge, global.lastRtt || 5);

    try {
        const stats = fs.statfsSync('/app');
        observableResult.observe(storageUsageGauge, (stats.blocks - stats.bfree) * stats.bsize);
    } catch (e) {
        observableResult.observe(storageUsageGauge, 0); 
    }
    
    // Only use stable attributes as metric labels to avoid Prometheus series explosion.
    // Dynamic values (playlist, sync status, last_sync) are reported via MQTT telemetry instead.
    observableResult.observe(infoGauge, 1, {
        version: '2.0.1',
        ip_address: localIp,
    });
}, [cpuGauge, memoryGauge, networkRttGauge, syncProgressGauge, storageUsageGauge, uptimeGauge, infoGauge]);

const setPlaylist = (name) => { currentPlaylist = name; };
const setSyncState = (status, progress) => {
    currentSyncProgress = progress;
    if (progress === 100) lastSyncTimestamp = Date.now();
};

module.exports = { meter, logger, setPlaylist, setSyncState };

logger.info("AUDIT: Telemetry system operational.");
