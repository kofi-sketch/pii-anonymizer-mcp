FROM node:18-alpine

LABEL maintainer="@kofi.owusu"
LABEL description="PII Anonymizer — local text sanitization. Zero network calls."

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --production

COPY engine.js server.js cli.js scan.js ./
COPY pii-config.example.json ./

# CLI: pipe text in, get anonymized text out on STDOUT
ENTRYPOINT ["node"]
CMD ["cli.js"]
