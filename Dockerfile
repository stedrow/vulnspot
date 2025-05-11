FROM cgr.dev/chainguard/python:latest-dev AS builder

# Set environment variables
ENV LANG=C.UTF-8
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/app/venv/bin:$PATH"

# Switch to root for installing Grype
USER root

# Install Grype
RUN apk update && \
    apk add --no-cache curl && \
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Set working directory
WORKDIR /app

# Create and activate virtual environment
RUN python -m venv /app/venv

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Final stage
FROM cgr.dev/chainguard/python:latest

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PATH="/venv/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /app/venv /venv

# Copy Grype binary from builder
COPY --from=builder /usr/local/bin/grype /usr/local/bin/grype

# Copy application code
COPY ./app /app
COPY ./templates /app/templates

# Volume for SQLite database
VOLUME /app/data

# Expose port
EXPOSE 8000

# Command to run the application
ENTRYPOINT ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"] 