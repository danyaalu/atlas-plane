# syntax=docker/dockerfile:1.7

FROM node:20-alpine
WORKDIR /bridge

RUN apk add --no-cache openssh-client \
  && apk add --no-cache --virtual .build-deps python3 py3-setuptools make g++ \
  && npm install --global --omit=dev wetty \
  && apk del .build-deps

RUN addgroup -S app && adduser -S app -G app \
  && mkdir -p /keys \
  && chown app:app /keys \
  && chmod 700 /keys

USER app
EXPOSE 3002
CMD ["sh", "-c", "if [ -n \"$SSH_TARGET_HOST\" ] && [ -n \"$SSH_KEY_FILE\" ]; then exec wetty --port 3002 --base / --command '/bin/sh -lc \"ssh -i /keys/${SSH_KEY_FILE} ${SSH_USER}@${SSH_TARGET_HOST}\"'; else echo 'SSH_TARGET_HOST/SSH_KEY_FILE not set, starting interactive shell bridge'; exec wetty --port 3002 --base / --command '/bin/sh'; fi"]
