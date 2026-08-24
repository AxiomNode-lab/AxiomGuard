FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json tsconfig.json ./
RUN npm ci
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:22-alpine
LABEL org.opencontainers.image.source="https://github.com/AxiomNode-lab/AxiomGuard"
LABEL org.opencontainers.image.url="https://github.com/AxiomNode-lab/AxiomGuard"
LABEL org.opencontainers.image.documentation="https://github.com/AxiomNode-lab/AxiomGuard#readme"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.title="AxiomGuard"
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/dist ./dist
USER node
ENTRYPOINT ["node", "/app/dist/cli.js"]
CMD ["--help"]
