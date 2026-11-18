.PHONY: install lint test audit leak-check all

install:
	uv sync --all-extras

lint:
	@echo "--- ruff check ---"
	uv run ruff check . && uv run ruff format --check .

test:
	@echo "--- pytest ---"
	uv run pytest -q

audit:
	@echo "--- pip-audit ---"
	uv run pip-audit --skip-editable

leak-check:
	@echo "--- publication leak check ---"
	PYTHONUTF8=1 uv run python scripts/check_publication_leaks.py

all: lint test audit leak-check
