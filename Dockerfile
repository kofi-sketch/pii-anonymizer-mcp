FROM node:22-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --production

COPY engine.js cli.js scan.js server.js ./

ENTRYPOINT ["node", "cli.js"]
