FROM node:20-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

FROM node:20-alpine AS runner
# openssl: cert operations; chrony: one-shot NTP sync on startup (#115)
RUN apk add --no-cache openssl chrony
WORKDIR /app
ENV NODE_ENV=production
COPY --from=builder /app/node_modules ./node_modules
COPY . .
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Both /app/cache and /app/secrets must be writable by the non-root user.
# security.js writes device key/CSR/cert under /app/secrets; without this the
# daemon EACCES-crashes on any node that does not bind-mount a secrets volume
# (e.g. the load-test screen nodes in docker-compose.screens.yml).
RUN mkdir -p /app/cache /app/secrets && \
    addgroup -S app && adduser -S -G app app && \
    chown -R app:app /app/cache /app/secrets
USER app

# Hardware player daemon port
EXPOSE 4000
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:4000/health || exit 1

ENTRYPOINT ["/entrypoint.sh"]
