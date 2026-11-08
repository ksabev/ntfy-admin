# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY web ./web
ARG VERSION=dev
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/ntfy-admin . \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="ntfy-admin" \
      org.opencontainers.image.description="Web admin panel for self-hosted ntfy: users, access rules, tokens, onboarding QR codes" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/ksabev/ntfy-admin"
COPY --from=build /out/ntfy-admin /ntfy-admin
COPY --from=build --chown=65532:65532 /out/data /data
ENV NTFY_ADMIN_DATA_DIR=/data
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD ["/ntfy-admin", "healthcheck"]
ENTRYPOINT ["/ntfy-admin"]
