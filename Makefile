VENV    := .venv
PY      := $(VENV)/bin/python
PIP     := $(VENV)/bin/pip
HOST    ?= 127.0.0.1
PORT    ?= 5000
RELOAD  ?= 1
URL     := http://$(HOST):$(PORT)

.DEFAULT_GOAL := web
.PHONY: help web watch serve run cli install clean

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

$(VENV)/bin/activate: requirements.txt
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	@touch $(VENV)/bin/activate

install: $(VENV)/bin/activate ## Create the virtualenv and install dependencies

.env:
	@cp .env.example .env
	@echo "Created .env — fill in CIAM_TENANT_SUBDOMAIN and CIAM_CLIENT_ID, then rerun."
	@exit 1

web: install .env ## Start the browser UI, open it, reload on save
	@echo "Serving $(URL) (reload=$(RELOAD))"
	@( sleep 2; $(PY) -c "import webbrowser; webbrowser.open('$(URL)')" ) &
	@HOST=$(HOST) PORT=$(PORT) FLASK_DEBUG=$(RELOAD) $(PY) web.py

watch: web ## Alias for 'web'

serve: ## Start the browser UI without the reloader
	@$(MAKE) web RELOAD=0

run: web ## Alias for 'web'

cli: install .env ## Start the console UI
	@$(PY) main.py

clean: ## Remove the virtualenv and bytecode caches
	rm -rf $(VENV)
	find . -name __pycache__ -type d -exec rm -rf {} +
