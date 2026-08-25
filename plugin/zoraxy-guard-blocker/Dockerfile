# Builds the zoraxy-guard-blocker plugin binary.
#
# Zoraxy plugins are plain executables that Zoraxy itself launches from its
# plugin folder — there is no "plugin container". This Dockerfile is only a
# reproducible way to cross-compile the binary; extract it afterwards, e.g.:
#
#   docker build --platform linux/amd64 -t zgb-build .
#   docker create --name zgb-extract zgb-build
#   docker cp zgb-extract:/out/zoraxy-guard-blocker ./zoraxy-guard-blocker
#   docker rm zgb-extract
#
# Then copy the resulting binary into Zoraxy's plugin directory, see README.md.

FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY . .
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/zoraxy-guard-blocker .

FROM scratch AS export
COPY --from=build /out/zoraxy-guard-blocker /out/zoraxy-guard-blocker
