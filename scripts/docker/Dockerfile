# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

# Multi-stage builder to avoid polluting users environment with wrong
# architecture binaries.
ARG VERSION

FROM golang:${VERSION} AS builder

ARG CGO_ENABLED=0
ARG BUILD_TAGS

WORKDIR /go/src/github.com/openbao/openbao
COPY . .

RUN make bootstrap \
  && CGO_ENABLED=$CGO_ENABLED BUILD_TAGS="${BUILD_TAGS}" OPENBAO_DEV_BUILD=1 sh -c "'./scripts/build.sh'"

# Docker Image

FROM alpine:3.21

# Create an openbao user and group first so the IDs get set the same way,
# even as the rest of this may change over time.
RUN addgroup openbao && \
    adduser -S -G openbao openbao

# Set up certificates, our base tools, and OpenBao.
RUN set -eux; \
    apk add --no-cache ca-certificates libcap su-exec dumb-init tzdata

COPY --from=builder /go/src/github.com/openbao/openbao/bin/bao /bin/bao
RUN ln -s /bin/bao /bin/vault

# /openbao/logs is made available to use as a location to store audit logs, if
# desired; /openbao/file is made available to use as a location with the file
# storage openbao, if desired; the server will be started with /openbao/config as
# the configuration directory so you can add additional config files in that
# location.
RUN mkdir -p /openbao/logs && \
    mkdir -p /openbao/file && \
    mkdir -p /openbao/config && \
    chown -R openbao:openbao /openbao

# Expose the logs directory as a volume since there's potentially long-running
# state in there
VOLUME /openbao/logs

# Expose the file directory as a volume since there's potentially long-running
# state in there
VOLUME /openbao/file

# 8200/tcp is the primary interface that applications use to interact with
# OpenBao.
EXPOSE 8200

# The entry point script uses dumb-init as the top-level process to reap any
# zombie processes created by OpenBao sub-processes.
COPY ./scripts/docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["docker-entrypoint.sh"]

# By default you'll get a single-node development server that stores everything
# in RAM and bootstraps itself. Don't use this configuration for production.
CMD ["server", "-dev"]
