FROM node:23-alpine

WORKDIR /app

COPY . /app

RUN addgroup -S nodegroup && adduser -S nodeuser -G nodegroup

RUN chown nodeuser:nodegroup /app

USER nodeuser

RUN npm ci && npm cache clean --force

EXPOSE 3000

ENTRYPOINT ["npm", "start"]