VENV=venv
PYTHON=$(VENV)/bin/python3
SCANNER=bin/scanner
DITECTOR_OUTPUT=data/ditector_results.jsonl

.PHONY: setup update scan watch wait

setup:
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install -r requirements.txt

update:
	git pull origin refactor/dynamic_containers_analysis
	$(VENV)/bin/pip install -r requirements.txt

scan:
	$(PYTHON) $(SCANNER) --seed --source ditector --file $(DITECTOR_OUTPUT) -v

watch:
	$(PYTHON) $(SCANNER) --watch --source ditector --file $(DITECTOR_OUTPUT) -v

wait:
	$(PYTHON) $(SCANNER) --wait-only -v
