## Dockerfile adapted from https://docusaurus.community/knowledge/deployment/docker/.

## Start with a base image containing NodeJS so we can build Docusaurus.
FROM node:lts@sha256:915acd9e9b885ead0c620e27e37c81b74c226e0e1c8177f37a60217b6eabb0d7

## Enable corepack.
RUN corepack enable

## Set the working directory to `/opt/docusaurus`.
VOLUME /opt/docusaurus
WORKDIR /opt/docusaurus

## Expose the port that Docusaurus will run on.
EXPOSE 3000

## Run the development server.
CMD [ -d "node_modules" ] && npm run start -- --host 0.0.0.0 --poll 1000 || npm install && npm run start -- --host 0.0.0.0 --poll 1000
