ifndef $(GRPC_PORT)
	GRPC_PORT := 50091
endif
ifndef $(GRPC_HOST)
	GRPC_HOST := localhost
endif
ifndef $(USE_DOCKER)
	USE_DOCKER := false
endif
ifndef $(SWH_CONFIG)
	SWH_CONFIG := swh
endif

DOCKER_IMAGE_NAME := osv_py

.PHONY: build requirements

build: Dockerfile requirements.txt
	docker build -t $(DOCKER_IMAGE_NAME) .

requirements: requirements.txt
	python3 -m pip install -r requirements.txt

.PRECIOUS: *.py
FORCE:

.ONESHELL:
src/%.py: FORCE
	if $(USE_DOCKER); then
		clear
		@docker run -it -v "$$(pwd)/data":/home/user/OSV/data -v "$$(pwd)/src":/home/user/OSV/src $(DOCKER_IMAGE_NAME) python -u $@ $(args)
	else
		clear
		@python -u $@ $(args)
	fi

shell: build src/shell.py

data/%/graph:
	cd swh-graph/java/target
	java -Xmx12G -cp swh-graph-2.3.0.jar org.softwareheritage.graph.rpc.GraphServer ../../../$@
