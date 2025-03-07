FROM --platform=$BUILDPLATFORM golang:1.22.4-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

ARG TARGETARCH TARGETOS

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o rules-db ./cmd

FROM alpine:latest

RUN apk --no-cache add ca-certificates

COPY --from=builder /app/rules-db /usr/local/bin/rules-db

COPY --from=builder /app/data ./data

CMD ["/usr/local/bin/rules-db"]
