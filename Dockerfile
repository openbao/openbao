# OpenBao container image for Dokploy / Docker deployment
FROM openbao/openbao:latest

# Expose OpenBao API port
EXPOSE 8200

# Copy deployment config into OpenBao configuration directory
COPY deploy/config.hcl /openbao/config/config.hcl

USER openbao

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["server", "-config=/openbao/config/config.hcl"]
