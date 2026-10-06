FROM node:26.10.0-alpine@sha256:0b36e8c136b94cd4fcf02188228e76c31ad5872eef3fec8cbd2eee500cfd9e80 AS build
WORKDIR /app
COPY package*.json tsconfig.json ./
RUN npm ci --ignore-scripts
COPY src ./src
RUN npm run build

FROM node:26.10.0-alpine@sha256:0b36e8c136b94cd4fcf02188228e76c31ad5872eef3fec8cbd2eee500cfd9e80
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
