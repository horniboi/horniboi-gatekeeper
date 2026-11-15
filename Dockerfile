FROM node:24-slim
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY server.js ./
COPY artifacts ./artifacts
ENV NODE_ENV=production
CMD ["node", "server.js"]
