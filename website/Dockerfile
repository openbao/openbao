## Dockerfile adapted from https://docusaurus.community/knowledge/deployment/docker/.

## Start with a base image containing NodeJS so we can build Docusaurus.
FROM node:lts

## Enable corepack.
RUN corepack enable

## Set the working directory to `/opt/docusaurus`.
VOLUME /opt/docusaurus
WORKDIR /opt/docusaurus

## Expose the port that Docusaurus will run on.
EXPOSE 3000

## Run the development server.
CMD [ -d "node_modules" ] && npm run start -- --host 0.0.0.0 --poll 1000 || npm install && npm run start -- --host 0.0.0.0 --poll 1000
