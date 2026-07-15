# Dockerfile used by GoReleaser (.goreleaser.yaml dockers section).
# The f2b binary is built by GoReleaser and copied into the build context.
FROM alpine:3.22
RUN apk --no-cache add ca-certificates
COPY f2b /usr/local/bin/
ENTRYPOINT ["f2b"]
