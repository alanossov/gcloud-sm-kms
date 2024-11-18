FROM golang:1.23.2-alpine3.20 AS builder

WORKDIR /app

COPY . /app
RUN go mod download && go build main

FROM alpine:latest as runner

WORKDIR /app

COPY --from=builder /app/main main

CMD ["/app/main"]