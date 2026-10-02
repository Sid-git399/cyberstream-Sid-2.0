.PHONY: up down ps logs build migrate test-generator test-backend test-streaming test-all clean

up:
	docker compose up -d

down:
	docker compose down

ps:
	docker compose ps

logs:
	docker compose logs -f

build:
	docker compose build

migrate:
	docker compose run --rm migrate

test-generator:
	cd generator && python -m pytest tests/ -v

test-backend:
	cd backend && python -m pytest tests/ -v

test-streaming:
	cd streaming && python -m pytest tests/ -v

test-all: test-generator test-backend test-streaming

clean:
	docker compose down -v
