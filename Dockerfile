# Build stage
FROM --platform=$BUILDPLATFORM golang:1.21-alpine AS builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

# Copy go mod files
COPY go.mod ./

# Download dependencies
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Run go mod tidy to ensure go.sum is up to date
RUN go mod tidy

# Build the application with correct architecture
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /nginx-log-exporter

# Final stage
FROM alpine:3.19

WORKDIR /

# Copy binary from builder
COPY --from=builder /nginx-log-exporter /nginx-log-exporter

# Run as non-root user
RUN adduser -D -h /app exporter
USER exporter

EXPOSE 9113

ENTRYPOINT ["/nginx-log-exporter"]