FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY main.go ui.html ./
RUN go mod init coraza-waf-defense && \
    go get github.com/corazawaf/coraza/v3@v3.2.1 github.com/corazawaf/coraza-coreruleset/v4@v4.3.0 && \
    go mod tidy && \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /coraza-waf-server main.go

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /coraza-waf-server /usr/local/bin/coraza-waf-server
EXPOSE 80 8080
ENTRYPOINT ["/usr/local/bin/coraza-waf-server"]
