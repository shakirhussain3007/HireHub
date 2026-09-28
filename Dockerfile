FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN apk add --no-cache python3 make g++ && npm install --omit=dev && apk del python3 make g++
COPY . .
ENV NODE_ENV=production DB_PATH=/data/jobs.db PORT=3000
VOLUME /data
EXPOSE 3000
CMD ["node","server.js"]
