FROM golang:1.27-alpine AS builder

WORKDIR /app

COPY go.sum, go.mod  . 

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o server .



FROM alpine AS runner

WORKDIR /app

COPY --from=builder /app/server ./server

ENTRYPOINT "./server"
