.PHONY: all install test clean format lint help

APP      := integrity_check.py
TEST     := test_integrity.py
BASELINE := .metadata_store.json

help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  all       install deps + run tests (default)"
	@echo "  install   install dev dependencies (pytest)"
	@echo "  test      run pytest suite"
	@echo "  clean     remove cache, baselines, temp files"
	@echo "  format    auto-format with autopep8 (if installed)"
	@echo "  lint      run flake8 (if installed)"

all: install test

install:
	pip3 install -r requirements-dev.txt 2>/dev/null || true

test:
	python3 -m pytest $(TEST) -v --tb=short

clean:
	rm -rf __pycache__ .pytest_cache *.pyc $(BASELINE) $(BASELINE).tmp
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

format:
	autopep8 --in-place --aggressive --aggressive $(APP) $(TEST) 2>/dev/null || echo "Install autopep8: pip3 install autopep8"

lint:
	flake8 $(APP) $(TEST) 2>/dev/null || echo "Install flake8: pip3 install flake8"
