FROM node:22-slim

WORKDIR /app

COPY package.json package-lock.json ./
COPY backend/package.json backend/package.json
COPY frontend/package.json frontend/package.json
RUN npm ci --include=dev

COPY . .
RUN npm run build

ENV NODE_ENV=production
ENV PORT=8080
EXPOSE 8080

CMD ["npm", "start"]
