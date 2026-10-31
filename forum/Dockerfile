FROM node:22-slim
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
# the app writes uploads and backups under /app/data, so that folder must belong to the non-root user
RUN mkdir -p /app/data/uploads /app/data/backups && chown -R node:node /app
USER node
CMD ["node", "src/server.js"]
