FROM python:3.12-slim

# Install Grype
RUN apt-get update && \
    apt-get install -y curl && \
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
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload", "--reload-dir", "/app"] 