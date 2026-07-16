# Dockerfile used by GoReleaser (.goreleaser.yaml dockers section).
# The f2b binary is built by GoReleaser and copied into the build context.
FROM alpine:3.22
RUN apk --no-cache add ca-certificates \
    && adduser -D -H -u 10001 f2b
COPY f2b /usr/local/bin/
USER f2b
HEALTHCHECK CMD ["f2b", "version"]
ENTRYPOINT ["f2b"]
