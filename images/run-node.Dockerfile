# gatehouse-run-node: the JS/TS ecosystem runner (plan §13).
# ESLint, Biome, TypeScript, Jest/Vitest. Users can override this image in
# gatehouse.yaml to pin the exact Node version their project uses.
FROM node:22-bookworm-slim

RUN npm install -g --no-fund --no-audit \
      eslint@9 \
      @biomejs/biome@1.9 \
      typescript@5.7 \
      vitest@2

USER node
WORKDIR /src
ENV HOME=/tmp npm_config_cache=/tmp/npm
ENTRYPOINT []
