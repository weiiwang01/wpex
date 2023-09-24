FROM --platform=${BUILDPLATFORM:-linux/amd64} golang:1.21 as builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH
ARG WPEX_VERSION

WORKDIR /build

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-w -s -X main.version=${WPEX_VERSION}" -o wpex

FROM --platform=${TARGETPLATFORM:-linux/amd64} scratch

COPY --from=builder /build/wpex /bin/wpex

ENTRYPOINT ["/bin/wpex"]
