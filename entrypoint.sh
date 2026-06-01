#!/bin/sh
# One-shot NTP sync before starting the daemon (#115).
# Prevents daypart scheduling from firing at wrong times after power loss.
if command -v chronyd >/dev/null 2>&1; then
    echo "[NTP] Syncing clock via chrony..."
    chronyd -q 2>/dev/null && echo "[NTP] Clock synced OK" || echo "[NTP] WARNING: Time sync failed — proceeding with current clock"
fi

exec node server.js
