.PHONY: default build run run-dev stop clean test

APP_NAME := vulnspot
PYTHON_INTERPRETER := python3

# Default target when just `make` is run
default: run-dev

# Build the Docker image
build:
	@echo "Building Docker image for $(APP_NAME)..."
	docker-compose build

# Run the application using docker-compose (builds if necessary)
run: run-dev

# Run the development server inside Docker using docker-compose (builds if necessary)
run-dev:
	@echo "Starting $(APP_NAME) development server with docker-compose (reload enabled)..."
	@echo "Access at http://localhost:8000"
	docker-compose -f docker-compose.dev.yml up --build

# Stop the docker-compose services
stop:
	@echo "Stopping $(APP_NAME) docker-compose services..."
	docker-compose down

# Clean up Docker resources and local artifacts
clean: stop
	@echo "Cleaning up Docker resources (volumes, orphans)..."
	docker-compose down -v --remove-orphans
	@echo "Removing __pycache__, .pytest_cache, and local dev database..."
	find . -type d -name "__pycache__" -exec rm -rf {} + || true
	rm -rf .pytest_cache || true
	rm -f data/vuln_scanner.db || true
	@echo "Cleanup complete."

# Placeholder for running tests
test:
	@echo "Running tests for $(APP_NAME)... (Not yet implemented)"
	# Example: $(PYTHON_INTERPRETER) -m pytest 