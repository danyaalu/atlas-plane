# syntax=docker/dockerfile:1.7

FROM node:20-alpine
WORKDIR /bridge

COPY docker/ssh-bridge/package.json ./package.json
RUN npm install --omit=dev

COPY docker/ssh-bridge/server.mjs ./server.mjs

RUN addgroup -S app && adduser -S app -G app \
  && mkdir -p /keys \
  && chown app:app /keys \
  && chmod 700 /keys

USER app
EXPOSE 3002
CMD ["npm", "run", "start"]
