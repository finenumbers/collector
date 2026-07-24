FROM node:24-alpine AS web
WORKDIR /src/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.26-alpine AS backend
ARG VERSION=dev
WORKDIR /src
RUN apk add --no-cache ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/collector ./cmd/collector

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -g 1000 collector && adduser -D -u 1000 -G collector collector
WORKDIR /app
COPY --from=backend /out/collector /app/collector
COPY --from=web /src/web/dist /app/web
COPY migrations /app/migrations
USER collector
EXPOSE 8080 1514/udp
ENTRYPOINT ["/app/collector"]
