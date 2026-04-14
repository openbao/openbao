# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

# This is {docker.io,quay.io,ghcr.io}/openbao/openbao{,-hsm}.
FROM alpine:3.23 AS default

COPY LICENSE /licenses/mozilla.txt

# Create a non-root user to run the software.
RUN addgroup openbao && adduser -S -G openbao openbao

RUN apk add --no-cache ca-certificates libcap su-exec dumb-init tzdata gcompat

# The OpenBao binary is built externally in CI and copied into the container
# build.
ARG BIN_NAME
COPY ${BIN_NAME} /bin/
RUN ln -s /bin/${BIN_NAME} /bin/vault

# /openbao/logs is made available to use as a location to store audit logs, if
# desired; /openbao/file is made available to use as a location with the file
# storage backend, if desired; the server will be started with /openbao/config
# as the configuration directory so you can add additional config files in that
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

# Use the OpenBao user as the default user for starting this container.
USER openbao

# The entry point script uses dumb-init as the top-level process to reap any
# zombie processes created by OpenBao sub-processes.
COPY .release/docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["docker-entrypoint.sh"]

# By default you'll get a single-node development server that stores everything
# in RAM and bootstraps itself. Don't use this configuration for production.
CMD ["server", "-dev", "-dev-no-store-token"]


# This is {docker.io,quay.io,ghcr.io}/openbao/openbao{,-hsm}-ubi.
FROM registry.access.redhat.com/ubi10-minimal:10.1 AS ubi

COPY LICENSE /licenses/mozilla.txt

# Set up ca-certificates & base tooling.
RUN microdnf install -y ca-certificates gnupg openssl libcap tzdata procps shadow-utils util-linux

# Create a non-root user to run the software.
RUN groupadd --gid 1000 openbao && \
    adduser --uid 100 --system -g openbao openbao && \
    usermod -a -G root openbao

# The OpenBao binary is built externally in CI and copied into the container
# build.
ARG BIN_NAME
COPY ${BIN_NAME} /bin/
RUN ln -s /bin/${BIN_NAME} /bin/vault

# /openbao/logs is made available to use as a location to store audit logs, if
# desired; /openbao/file is made available to use as a location with the file
# storage backend, if desired; the server will be started with /openbao/config
# as the configuration directory so you can add additional config files in that
# location.
ENV HOME=/home/openbao
RUN mkdir -p /openbao/logs && \
    mkdir -p /openbao/file && \
    mkdir -p /openbao/config && \
    mkdir -p $HOME && \
    chown -R openbao /openbao && chown -R openbao $HOME && \
    chgrp -R 0 $HOME && chmod -R g+rwX $HOME && \
    chgrp -R 0 /openbao && chmod -R g+rwX /openbao

# Expose the logs directory as a volume since there's potentially long-running
# state in there
VOLUME /openbao/logs

# Expose the file directory as a volume since there's potentially long-running
# state in there
VOLUME /openbao/file

# 8200/tcp is the primary interface that applications use to interact with
# OpenBao.
EXPOSE 8200

# Use the OpenBao user as the default user for starting this container.
USER openbao

# The entry point script uses dumb-init as the top-level process to reap any
# zombie processes created by OpenBao sub-processes.
COPY .release/docker/ubi-docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["docker-entrypoint.sh"]

# By default you'll get a single-node development server that stores everything
# in RAM and bootstraps itself. Don't use this configuration for production.
CMD ["server", "-dev", "-dev-no-store-token"]


# This is {docker.io,quay.io,ghcr.io}/openbao/openbao-distroless.
FROM gcr.io/distroless/static:nonroot@sha256:f512d819b8f109f2375e8b51d8cfd8aafe81034bc3e319740128b7d7f70d5036 AS distroless

COPY LICENSE /licenses/mozilla.txt

# The OpenBao binary is built externally in CI and copied into the container
# build.
ARG BIN_NAME
COPY ${BIN_NAME} /bin/

# 8200/tcp is the primary interface that applications use to interact with
# OpenBao.
EXPOSE 8200

# By default you'll get a single-node development server that stores everything
# in RAM and bootstraps itself. Don't use this configuration for production.
ENTRYPOINT ["/bin/bao"]
CMD ["server", "-dev", "-dev-no-store-token"]
