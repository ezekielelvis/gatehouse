# gatehouse: the core daemon/CLI image (plan §13).
#
# Two-stage build: compile a fully static CGO-free binary, then ship it on a
# non-root distroless static base. The pure-Go SQLite driver (modernc) means no
# cgo and no libc, so this is a genuinely static ~single-file image.
FROM golang:1.27-bookworm AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=0.0.0-dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /gatehouse ./cmd/gatehouse

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /gatehouse /usr/bin/gatehouse
USER nonroot:nonroot
EXPOSE 7420
ENTRYPOINT ["/usr/bin/gatehouse"]
CMD ["serve", "--addr", "0.0.0.0:7420"]
