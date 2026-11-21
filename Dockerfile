# Sentra — single image for API/BFF and worker processes. Pin the base image digest in production.
FROM node:24-alpine AS web
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY tsconfig.json vite.config.mjs ./
COPY web ./web
COPY public ./public
RUN npm run build

FROM node:24-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts

FROM node:24-alpine
ENV NODE_ENV=production
WORKDIR /app
RUN addgroup -S sentra && adduser -S sentra -G sentra && mkdir -p /data/objects && chown -R sentra:sentra /data
COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY src ./src
COPY migrations ./migrations
COPY --from=web /app/public ./public
COPY scripts/sentra-ci.mjs ./scripts/sentra-ci.mjs
USER sentra
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD wget -qO- http://127.0.0.1:8080/api/health || exit 1
CMD ["node", "src/server.mjs"]
