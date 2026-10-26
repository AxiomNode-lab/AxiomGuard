FROM node:26.12.1-alpine@sha256:40cd011b55415bc894e45b02fdd5a5dfde056921b7d23a64c74f80497af48797 AS build
WORKDIR /app
COPY package*.json tsconfig.json ./
RUN npm ci --ignore-scripts
COPY src ./src
RUN npm run build

FROM node:26.12.1-alpine@sha256:40cd011b55415bc894e45b02fdd5a5dfde056921b7d23a64c74f80497af48797
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
