# ==============================================================================
# SecretShield Platform - Multi-Stage / Unified Production Dockerfile
# Combines: Node.js 22 + React 19 Frontend + Express API + Python 3 Scanner + Git
# ==============================================================================

FROM node:22-slim

# Install system dependencies:
# - python3: Powers SecretShield pattern engine, AST parser & validation scripts
# - git: Enables repository cloning, reflog analysis, and git object inspection
# - curl & ca-certificates: Required for secure repository cloning & container healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-minimal \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cache package manifests first to optimize Docker layer build caching
COPY package*.json ./

# Install npm dependencies (including build tools for Vite compilation)
RUN npm install

# Copy entire application source code
COPY . .

# Ensure entrypoint script is executable
RUN chmod +x ./docker-entrypoint.sh 2>/dev/null || true

# Pre-initialize sample git repository fixture for instant demo readiness
RUN python3 scripts/setup_sample_repo.py || true

# Compile Vite production frontend bundle
RUN npm run build

# Default runtime configuration
ENV NODE_ENV=production
ENV PORT=10000
ENV PYTHONDONTWRITEBYTECODE=1

# Expose Render default port (and customizable via $PORT)
EXPOSE 10000

# Container health monitoring
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:${PORT}/api/health || exit 1

# Auto-migrate/verify database schema on container boot before starting service
ENTRYPOINT ["/bin/sh", "./docker-entrypoint.sh"]

# Start unified Express server & static asset distributor
CMD ["npm", "start"]
