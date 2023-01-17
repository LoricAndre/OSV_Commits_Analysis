DOCKER_IMAGE_NAME := osv_py
CSV_FILE := data/osv.csv
DB_FILE := data/swh.db

.PHONY: build requirements

build: Dockerfile requirements.txt
	docker build -t $(DOCKER_IMAGE_NAME) --network=host .

requirements: requirements.txt
	python3 -m pip install -r requirements.txt

.PRECIOUS: *.py
FORCE:

.ONESHELL:
src/%.py: FORCE data/osv.csv
	clear
	@docker run -it -v "$$(pwd)/data":/home/user/OSV/data -v "$$(pwd)/src":/home/user/OSV/src $(DOCKER_IMAGE_NAME) python -u $@ $(args)

# Shell
shell: build src/shell.py

# graph.py
colorize: $(DB_FILE) src/graph.py

# Pull OSV data and create CSV file
$(CSV_FILE):
	./fetch.sh $(CSV_FILE)

# Create DB file from CSV
$(DB_FILE): $(CSV_FILE)
	sqlite3 --csv $@ ".import $< OSV"
