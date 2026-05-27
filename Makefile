.PHONY: install test lint

install:
	pip install -e sentinel/ -e bulwark/ -e covenant/ -e vault/ -e chronicle/ -e paladin/

test:
	python -m pytest

lint:
	ruff check . --select E,W,F
