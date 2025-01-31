# Use buildx syntax
FROM --platform=$BUILDPLATFORM golang:1.21-alpine AS builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

# Copy go mod files
COPY go.mod ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application with correct architecture
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /nginx-log-exporter

# Final stage
FROM --platform=$TARGETPLATFORM alpine:3.19

WORKDIR /

# Copy binary from builder
COPY --from=builder /nginx-log-exporter /nginx-log-exporter

# Run as non-root user
RUN adduser -D -h /app exporter
USER exporter

EXPOSE 9113

ENTRYPOINT ["/nginx-log-exporter"]