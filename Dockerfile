FROM golang:1.16 AS builder

WORKDIR /app

COPY .. .

RUN go mod download

RUN go get github.com/dgrijalva/jwt-go
RUN go get github.com/lib/pq
RUN go get golang.org/x/crypto/bcrypt

RUN go build -o main .

FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y postgresql-client

COPY --from=builder /app/main /usr/local/bin/main

WORKDIR /app

ENV POSTGRES_USER=postgres
ENV POSTGRES_PASSWORD=postgres
ENV POSTGRES_DB=go_test
ENV POSTGRES_HOST=db
ENV POSTGRES_PORT=5432

COPY create_db.sql /docker-entrypoint-initdb.d/create_db.sql

CMD ["main"]
