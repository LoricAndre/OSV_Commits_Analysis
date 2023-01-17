ifndef DOCKER_IMAGE_NAME
	DOCKER_IMAGE_NAME := osv_py
endif
ifndef USE_DOCKER
	USE_DOCKER = true
endif
ifndef CSV_FILE
	CSV_FILE := data/osv.csv
endif
ifndef DB_FILE
	DB_FILE := data/swh.db
endif

.PHONY: build requirements

build: Dockerfile requirements.txt
	docker build -t $(DOCKER_IMAGE_NAME) --network=host .

requirements: requirements.txt
	python3 -m pip install -r requirements.txt

.PRECIOUS: *.py
FORCE:

.ONESHELL:
src/%.py: FORCE data/osv.csv
	if $(USE_DOCKER); then
		clear
		echo "Running in docker"
		echo "$(USE_DOCKER)"
		@docker run -it -v "$$(pwd)/data":/home/user/OSV/data -v "$$(pwd)/src":/home/user/OSV/src $(DOCKER_IMAGE_NAME) python -u $@ $(args)
	else
		clear
		@python3 -u $@ $(args)
	fi

# Shell
shell: build src/shell.py

# graph.py
colorize: $(DB_FILE) src/graph.py

# Pull OSV data and create CSV file
$(CSV_FILE):
	./src/fetch.sh $(CSV_FILE)

# Create DB file from CSV
$(DB_FILE): $(CSV_FILE)
	sqlite3 --csv $@ ".import $< OSV"


tunnel:
	ssh -L 50091:localhost:50091 -J $(SSH_USER)@ssh.enst.fr $(SSH_USER)@swh1.enst.fr
