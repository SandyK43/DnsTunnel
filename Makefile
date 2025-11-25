.PHONY: help build up down logs train-model generate-data clean test

# Default target
help:
	@echo "DNS Tunneling Detection Microservice"
	@echo ""
	@echo "Available targets:"
	@echo "  build          - Build Docker images"
	@echo "  up             - Start all services"
	@echo "  down           - Stop all services"
	@echo "  logs           - View logs"
	@echo "  train-model    - Train ML model with sample data"
	@echo "  generate-data  - Generate sample DNS logs"
	@echo "  clean          - Remove all containers and volumes"
	@echo "  test           - Run tests"
	@echo "  shell          - Open shell in API container"

# Build Docker images
build:
	docker-compose build

# Start services
up:
	docker-compose up -d
	@echo "Services started!"
	@echo "API: http://localhost:8000"
	@echo "API Docs: http://localhost:8000/docs"
	@echo "Grafana: http://localhost:3000 (admin/admin123)"
	@echo "Prometheus: http://localhost:9090"

# Stop services
down:
	docker-compose down

# View logs
logs:
	docker-compose logs -f

# Train model with sample data
train-model:
	@echo "Generating sample baseline data and training model..."
	docker-compose exec api python scripts/train_model.py --format sample --num-samples 2000
	@echo "Model trained successfully!"

# Generate sample DNS logs
generate-data:
	@echo "Generating sample DNS logs..."
	docker-compose exec api python scripts/generate_sample_logs.py --benign 1000 --malicious 50 --format json
	@echo "Sample data generated!"

# Clean everything
clean:
	docker-compose down -v
	rm -rf models/*.pkl
	rm -rf data/*.log
	rm -rf logs/*.log

# Run tests
test:
	docker-compose exec api pytest tests/ -v

# Open shell in API container
shell:
	docker-compose exec api /bin/bash

# Initialize database
init-db:
	docker-compose exec api python -c "from api.database import init_db; init_db()"

# Quick start (build + up + train)
quickstart: build up
	@echo "Waiting for services to start..."
	@sleep 10
	@make train-model
	@echo ""
	@echo "✅ Quick start complete!"
	@echo "Access the API at http://localhost:8000/docs"

