# Staging-only derivative: add static BusyBox shell and HTTP probe to the
# upstream static OAuth proxy. No OS package manager or privileged entrypoint.
# Pin both image references by digest after image-provenance verification.
FROM busybox:1.36.1-musl AS probe
FROM ghcr.io/babs/mcp-auth-proxy:2.1.0
COPY --from=probe /bin/busybox /bin/busybox
COPY --from=probe /bin/busybox /bin/sh
