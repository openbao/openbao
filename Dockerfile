# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

#### DOCKERHUB DOCKERFILE ####
FROM alpine:3.21 as default

ARG BIN_NAME
# NAME and PRODUCT_VERSION are the name of the software in releases.hashicorp.com
# and the version to download. Example: NAME=openbao PRODUCT_VERSION=1.2.3.
ARG NAME=openbao
ARG PRODUCT_VERSION
ARG PRODUCT_REVISION

# Additional metadata labels used by container registries, platforms
# and certification scanners.
LABEL name="OpenBao" \
      maintainer="OpenBao <openbao@lists.lfedge.org>" \
      vendor="OpenBao" \
      version=${PRODUCT_VERSION} \
      release=${PRODUCT_REVISION} \
      revision=${PRODUCT_REVISION} \
      summary="OpenBao is a tool for securely accessing secrets." \
      description="OpenBao is a tool for securely accessing secrets. A secret is anything that you want to tightly control access to, such as API keys, passwords, certificates, and more. OpenBao provides a unified interface to any secret, while providing tight access control and recording a detailed audit log."

COPY LICENSE /licenses/mozilla.txt

# Set ARGs as ENV so that they can be used in ENTRYPOINT/CMD
ENV NAME=$NAME
ENV VERSION=$VERSION

# Create a non-root user to run the software.
RUN addgroup ${NAME} && adduser -S -G ${NAME} ${NAME}

ARG EXTRA_PACKAGES
RUN apk add --no-cache libcap su-exec dumb-init tzdata ${EXTRA_PACKAGES}

COPY $BIN_NAME /bin/

RUN ln -s /bin/${BIN_NAME} /bin/vault

# /vault/logs is made available to use as a location to store audit logs, if
# desired; /vault/file is made available to use as a location with the file
# storage backend, if desired; the server will be started with /vault/config as
# the configuration directory so you can add additional config files in that
# location.
RUN mkdir -p /openbao/logs && \
    mkdir -p /openbao/file && \
    mkdir -p /openbao/config && \
    chown -R ${NAME}:${NAME} /openbao

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
COPY .release/docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["docker-entrypoint.sh"]


# # By default you'll get a single-node development server that stores everything
# # in RAM and bootstraps itself. Don't use this configuration for production.
CMD ["server", "-dev", "-dev-no-store-token"]




#### UBI DOCKERFILE ####
FROM registry.access.redhat.com/ubi9-minimal:9.6 as ubi

ARG BIN_NAME
# PRODUCT_VERSION is the version built dist/$TARGETOS/$TARGETARCH/$BIN_NAME,
# which we COPY in later. Example: PRODUCT_VERSION=1.2.3.
ARG PRODUCT_VERSION
ARG PRODUCT_REVISION

# Additional metadata labels used by container registries, platforms
# and certification scanners.
LABEL name="OpenBao" \
      maintainer="OpenBao <openbao@lists.lfedge.org>" \
      vendor="OpenBao" \
      version=${PRODUCT_VERSION} \
      release=${PRODUCT_REVISION} \
      revision=${PRODUCT_REVISION} \
      summary="OpenBao is a tool for securely accessing secrets." \
      description="OpenBao is a tool for securely accessing secrets. A secret is anything that you want to tightly control access to, such as API keys, passwords, certificates, and more. OpenBao provides a unified interface to any secret, while providing tight access control and recording a detailed audit log."

COPY LICENSE /licenses/mozilla.txt

# Set ARGs as ENV so that they can be used in ENTRYPOINT/CMD
ENV NAME=$NAME
ENV VERSION=$VERSION

# Set up certificates, our base tools, and OpenBao. Unlike the other version of
# this (https://github.com/hashicorp/docker-vault/blob/master/ubi/Dockerfile),
# we copy in the OpenBao binary from CRT.
RUN set -eux; \
    microdnf install -y ca-certificates gnupg openssl libcap tzdata procps shadow-utils util-linux

# Create a non-root user to run the software.
RUN groupadd --gid 1000 openbao && \
    adduser --uid 100 --system -g openbao openbao && \
    usermod -a -G root openbao

# Copy in the new OpenBao from CRT pipeline, rather than fetching it from our
# public releases.
COPY $BIN_NAME /bin/

RUN ln -s /bin/${BIN_NAME} /bin/vault

# /vault/logs is made available to use as a location to store audit logs, if
# desired; /vault/file is made available to use as a location with the file
# storage backend, if desired; the server will be started with /vault/config as
# the configuration directory so you can add additional config files in that
# location.
ENV HOME /home/openbao
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

# The entry point script uses dumb-init as the top-level process to reap any
# zombie processes created by OpenBao sub-processes.
COPY .release/docker/ubi-docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["docker-entrypoint.sh"]

# Use the OpenBao user as the default user for starting this container.
USER openbao

# # By default you'll get a single-node development server that stores everything
# # in RAM and bootstraps itself. Don't use this configuration for production.
CMD ["server", "-dev", "-dev-no-store-token"]
