# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

# This is a helper stage that ensures the binary layer is always the same, no
# matter which base image it is copied into:
#
# 1. Always use /usr/bin/bao, not /bin/bao etc.
# 2. Apply the same file permissions across the /usr and /usr/bin directories.
#    Specifically, UBI is missing an u+w bit on /usr/bin that Alpine and
#    Distroless have.
#
# Together with SOURCE_DATE_EPOCH and rewrite-timestamp, this results in an
# identical binary layer digest across all distributions below, i.e., a given
# release binary is only ever pushed to a registry once, even if there is more
# than one container image flavor packaging it.
FROM scratch AS bin
ARG TARGETARCH
COPY --chmod=555 bin/${TARGETARCH}/bao /usr/bin/bao

# This is {docker.io,quay.io,ghcr.io}/openbao/openbao.
FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS default

COPY LICENSE /licenses/mozilla.txt

# Create a non-root user to run the software.
RUN addgroup openbao && adduser -S -G openbao openbao

RUN apk add --no-cache ca-certificates libcap su-exec dumb-init tzdata gcompat

# Copy the binary stage.
COPY --from=bin . /
RUN ln -s /usr/bin/bao /usr/bin/vault

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


# This is {docker.io,quay.io,ghcr.io}/openbao/openbao-ubi.
FROM registry.access.redhat.com/ubi10-minimal:10.2@sha256:b217fa65d8c21058887b18f005f587e47a17dd1281a5196ac88d01724a273dbd AS ubi
ARG VERSION="0.0.0-dev"
ARG REVISION="unknown"

COPY LICENSE /licenses/mozilla.txt

ARG LABEL_DESCRIPTION="OpenBao is a tool for securely accessing secrets. A secret is anything that you want to tightly control access to, such as API keys, passwords, certificates, and more. OpenBao provides a unified interface to any secret, while providing tight access control and recording a detailed audit log"

# Overwrite base image labels
# These labels are required by Red Hat
LABEL name="OpenBao" \
      maintainer="OpenBao <openbao@lists.openssf.org>" \
      vendor="OpenBao" \
      version="${VERSION}" \
      release="${VERSION}" \
      summary="OpenBao is a tool for securely accessing secrets" \
      description="${LABEL_DESCRIPTION}" \
      url="https://openbao.org" \
      build-date="" \
      com.redhat.component="" \
      com.redhat.license_terms="" \
      io.buildah.version="" \
      io.k8s.description="${LABEL_DESCRIPTION}" \
      io.k8s.display-name="OpenBao" \
      io.openshift.expose-services="8200/tcp:https" \
      vcs-ref="${REVISION}"

# Set up ca-certificates & base tooling.
RUN microdnf install -y ca-certificates gnupg openssl libcap tzdata procps shadow-utils util-linux

# Create a non-root user to run the software.
RUN groupadd --gid 1000 openbao && \
    adduser --uid 100 --system -g openbao openbao && \
    usermod -a -G root openbao

# Copy the binary stage.
COPY --from=bin . /
RUN ln -s /usr/bin/bao /usr/bin/vault

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
FROM gcr.io/distroless/static:nonroot@sha256:d29e660cc75a5b6b1334e03c5c81ccf9bc0884a002c6000dbf0fb96034814478 AS distroless

COPY LICENSE /licenses/mozilla.txt

# Copy the binary stage.
COPY --from=bin . /

# 8200/tcp is the primary interface that applications use to interact with
# OpenBao.
EXPOSE 8200

# By default you'll get a single-node development server that stores everything
# in RAM and bootstraps itself. Don't use this configuration for production.
ENTRYPOINT ["/usr/bin/bao"]
CMD ["server", "-dev", "-dev-no-store-token"]
