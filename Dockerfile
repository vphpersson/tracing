FROM golang:1.27-alpine AS builder

RUN apk update \
  && apk upgrade --no-cache \
  && apk add --no-cache git

WORKDIR /usr/src/app

COPY . .
RUN go mod download && go mod verify

RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags="-s -w" -installsuffix cgo -o /usr/src/bin/app ./cmd/tracing_service

FROM scratch

COPY --from=builder /usr/src/bin/app tracing
USER 1000

ENTRYPOINT ["./tracing"]
