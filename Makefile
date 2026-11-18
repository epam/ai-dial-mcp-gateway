.PHONY: install lint test audit leak-check all

install:
	python -m pip install -e ".[dev]"

lint:
	@echo "--- ruff check ---"
	ruff check . && ruff format --check .

test:
	@echo "--- pytest ---"
	pytest -q

audit:
	@echo "--- pip-audit ---"
	PYTHONUTF8=1 pip-audit --skip-editable

leak-check:
	@echo "--- publication leak check ---"
	PYTHONUTF8=1 python scripts/check_publication_leaks.py

all: lint test audit leak-check