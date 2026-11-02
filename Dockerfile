FROM node:26.13.0-alpine@sha256:c6ad9e9c1d80f6eb607c26b4b0a132ff7a2344fad1c78ea3baa2a7d4c8de6d94 AS build
WORKDIR /app
COPY package*.json tsconfig.json ./
RUN npm ci --ignore-scripts
COPY src ./src
RUN npm run build

FROM node:26.13.0-alpine@sha256:c6ad9e9c1d80f6eb607c26b4b0a132ff7a2344fad1c78ea3baa2a7d4c8de6d94
LABEL org.opencontainers.image.source="https://github.com/AxiomNode-lab/AxiomGuard"
LABEL org.opencontainers.image.url="https://github.com/AxiomNode-lab/AxiomGuard"
LABEL org.opencontainers.image.documentation="https://github.com/AxiomNode-lab/AxiomGuard#readme"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.title="AxiomGuard"
LABEL org.opencontainers.image.description="Zero-dependency secret scanner CLI: mount a repository at /workspace and run `scan /workspace`."
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/dist ./dist
# The scan root is a mount point, not the image's own files.
WORKDIR /workspace
USER node
ENTRYPOINT ["node", "/app/dist/cli.js"]
CMD ["--help"]
