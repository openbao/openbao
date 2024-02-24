# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

# ===================================
# 
#   Release image
#
# ===================================
FROM alpine:latest AS release-default

ARG BIN_NAME=consul-template
# Export BIN_NAME for the CMD below, it can't see ARGs directly.
ENV BIN_NAME=$BIN_NAME
ARG PRODUCT_VERSION
ARG PRODUCT_REVISION
ARG PRODUCT_NAME=$BIN_NAME
# TARGETARCH and TARGETOS are set automatically when --platform is provided.
ARG TARGETOS TARGETARCH

LABEL maintainer="Consul Team <consul@hashicorp.com>"
# version label is required for build process
LABEL version=$PRODUCT_VERSION
LABEL revision=$PRODUCT_REVISION

# These are the defaults, this makes them explicit and overridable.
ARG UID=100
ARG GID=1000
# Create a non-root user to run the software.
RUN addgroup -g ${GID} ${BIN_NAME} \
    && adduser -u ${UID} -S -G ${BIN_NAME} ${BIN_NAME}

# where the build system stores the builds
COPY ./dist/$TARGETOS/$TARGETARCH/$BIN_NAME /bin/

# entrypoint
COPY ./.release/docker-entrypoint.sh /bin/
ENTRYPOINT ["/bin/docker-entrypoint.sh"]

USER ${BIN_NAME}:${BIN_NAME}
CMD /bin/$BIN_NAME

