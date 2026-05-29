# Clean-room runtime for AutoSec.
# - node 20, git, gh, claude CLI
# - native build toolchain so node-canvas / node-gyp deps install cleanly
FROM node:20-bookworm

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git gnupg jq python3 make g++ pkg-config \
      libcairo2-dev libpango1.0-dev libjpeg-dev libgif-dev librsvg2-dev libpixman-1-dev \
    && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
       | gpg --dearmor -o /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
       > /etc/apt/sources.list.d/github-cli.list \
    && apt-get update && apt-get install -y --no-install-recommends gh \
    && rm -rf /var/lib/apt/lists/*

RUN npm install -g @anthropic-ai/claude-code

WORKDIR /autosec
COPY package.json package-lock.json* ./
RUN npm install --no-audit --no-fund --registry=https://registry.npmjs.org/

COPY bin ./bin
COPY src ./src
COPY prompts ./prompts

ENV AUTOSEC_NPM_REGISTRY=https://registry.npmjs.org/
ENTRYPOINT ["node", "/autosec/bin/autosec.js"]
