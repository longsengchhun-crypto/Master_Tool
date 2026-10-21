# SENTRIX Console. NOT BUILT OR RUN in the authoring environment (no Docker available); treat as a starting point.
# Build from the repository root:  docker build -f infrastructure/Dockerfile -t sentrix-console .
FROM node:24-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
COPY apps/admin/package.json apps/admin/
COPY packages/contracts/package.json packages/contracts/
# Only the console's workspace graph is installed (the desktop app and Rust crates are not needed here).
RUN npm ci --workspace @sentrix/admin --include-workspace-root
COPY packages/contracts packages/contracts
COPY apps/admin apps/admin
RUN npm run build -w @sentrix/admin

FROM node:24-slim
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1
WORKDIR /app
RUN useradd --system --uid 10001 --create-home app
COPY --from=build --chown=app:app /app /app
USER app
EXPOSE 3100
# Secrets (DATABASE_URL, SESSION_SECRET, DEVICE_TOKEN_PEPPER) come from the platform's secret store, never from the image.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD node -e "fetch('http://127.0.0.1:3100/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["npm", "run", "start", "-w", "@sentrix/admin"]
