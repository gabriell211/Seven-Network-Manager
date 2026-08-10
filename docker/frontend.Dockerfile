FROM node:24.18.1-bookworm-slim AS deps
WORKDIR /src
RUN corepack enable && corepack prepare pnpm@11.21.0 --activate
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY apps/frontend/package.json ./apps/frontend/package.json
COPY packages/ui/package.json ./packages/ui/package.json
RUN pnpm install --frozen-lockfile

FROM node:24.18.1-bookworm-slim AS build
WORKDIR /src
RUN corepack enable && corepack prepare pnpm@11.21.0 --activate
COPY --from=deps /src/node_modules ./node_modules
COPY --from=deps /src/apps/frontend/node_modules ./apps/frontend/node_modules
COPY --from=deps /src/packages/ui/node_modules ./packages/ui/node_modules
COPY . .
RUN pnpm --filter @seven-network-manager/frontend build

FROM node:24.18.1-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production
ENV HOSTNAME=0.0.0.0
ENV PORT=3000
RUN useradd --system --uid 10003 --create-home snm-web
COPY --from=build --chown=10003:10003 /src/apps/frontend/.next/standalone ./
COPY --from=build --chown=10003:10003 /src/apps/frontend/.next/static ./apps/frontend/.next/static
COPY --from=build --chown=10003:10003 /src/apps/frontend/public ./apps/frontend/public
USER 10003:10003
EXPOSE 3000
CMD ["node", "apps/frontend/server.js"]
