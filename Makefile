.PHONY: test up down

test:
	PYTHONPATH=worker pytest tests/ -v

up:
	docker compose up --build

down:
	docker compose down -v
