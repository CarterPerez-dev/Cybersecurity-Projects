FROM alpine:3.19

RUN apk add --no-cache ca-certificates curl

# Create non-root user
RUN addgroup -g 1000 appuser && \
    adduser -D -u 1000 -G appuser appuser

WORKDIR /app

COPY --chown=appuser:appuser app.sh /app/
RUN chmod 755 /app/app.sh

# Switch to non-root user
USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

CMD ["/app/app.sh"]
