# Build a lightweight, secure container for ThreatPulse
FROM python:3.12-alpine

LABEL maintainer="Aleksei Zharkou <lyosha.zharkov.98@mail.ru>"
LABEL description="ThreatPulse: Zero-dependency SOC Threat Intelligence & IOC Triage CLI"

WORKDIR /app

# Security best practice: Create a non-privileged user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copy project files and install package
COPY --chown=appuser:appgroup pyproject.toml README.md ./
COPY --chown=appuser:appgroup threat_pulse/ ./threat_pulse/

RUN pip install --no-cache-dir .

# Switch to non-root user
USER appuser

ENTRYPOINT ["threat-pulse"]
CMD ["--help"]
