FROM python:3.13-alpine3.21

# Install Grype
RUN apk update && \
    apk add --no-cache curl && \
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY ./app /app
COPY ./templates /app/templates

# Volume for SQLite database
VOLUME /app/data

# Expose port
EXPOSE 8000

# Command to run the application
# Ensure the main module is correctly referenced if it's within a subdirectory of /app
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"] 