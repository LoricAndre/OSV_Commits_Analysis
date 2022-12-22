DOCKER_IMAGE_NAME := osv_py

.PHONY: build

build: Dockerfile requirements.txt
	docker build -t $(DOCKER_IMAGE_NAME) .

.PRECIOUS: *.py
FORCE:

shell: src/shell.py FORCE
	echo "Done"

src/%.py: FORCE
	docker run -it -v "$$(pwd)/data":/home/user/OSV/data -v "$$(pwd)/src":/home/user/OSV/src $(DOCKER_IMAGE_NAME) python -u $@ $(args)
