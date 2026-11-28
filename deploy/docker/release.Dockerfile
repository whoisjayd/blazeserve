# syntax=docker/dockerfile:1
# The published image: the release workflow's static binaries, copied in. Nothing runs
# during the build, so both architectures build in seconds without emulation.
# The context holds blaze-amd64, blaze-arm64 and an empty folder named empty.
FROM scratch
LABEL org.opencontainers.image.title="BlazeServe" \
      org.opencontainers.image.source="https://github.com/whoisjayd/blazeserve" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.description="A fast file server and transfer tool for large files" \
      org.opencontainers.image.documentation="https://github.com/whoisjayd/blazeserve/tree/main/docs" \
      io.artifacthub.package.logo-url="https://raw.githubusercontent.com/whoisjayd/blazeserve/main/docs/assets/logo-tile.svg" \
      io.artifacthub.package.readme-url="https://raw.githubusercontent.com/whoisjayd/blazeserve/main/README.md" \
      net.unraid.docker.icon="https://raw.githubusercontent.com/whoisjayd/blazeserve/main/docs/assets/logo-tile.svg"

ARG TARGETARCH
COPY --chmod=755 blaze-${TARGETARCH} /usr/local/bin/blaze
COPY --chown=10001:10001 empty /data
COPY --chmod=1777 empty /tmp

ENV BLAZE_INSTALL_CHANNEL=docker
USER 10001:10001
WORKDIR /data
EXPOSE 5949
ENTRYPOINT ["/usr/local/bin/blaze"]
CMD ["serve", "/data", "--host", "0.0.0.0", "--port", "5949"]
