.PHONY: venv install dev test lint run-domain run-email run-user run-ip kali

PYTHON ?= python3
VENV_DIR ?= .venv
VENV_PYTHON = $(VENV_DIR)/bin/python
VENV_PIP = $(VENV_PYTHON) -m pip

venv:
	$(PYTHON) -m venv $(VENV_DIR)

install: venv
	$(VENV_PIP) install --upgrade pip
	$(VENV_PIP) install -r requirements.txt
	$(VENV_PIP) install -e .

dev: install

test:
	$(VENV_PYTHON) -m pytest

lint:
	$(VENV_PYTHON) -m flake8 osint utils tests main.py

run-domain:
	$(VENV_PYTHON) -m osint domain $(DOMAIN)

run-email:
	$(VENV_PYTHON) -m osint email $(EMAIL)

run-user:
	$(VENV_PYTHON) -m osint user $(USER_HANDLE)

run-ip:
	$(VENV_PYTHON) -m osint ip $(IP)

kali:
	bash scripts/setup-kali.sh
