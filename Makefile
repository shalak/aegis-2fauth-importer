ifneq (,$(wildcard aegis.env))
include aegis.env
export
endif

ifndef DOCKER_IMAGE
$(error DOCKER_IMAGE is not set. Define it in aegis.env)
endif

IMAGE := $(DOCKER_IMAGE)
TAG := latest
FULL_IMAGE := $(IMAGE):$(TAG)
PLATFORMS := linux/amd64,linux/arm64
BUILDER := aegis-multiarch

.PHONY: help builder build push run test clean

.DEFAULT_GOAL := help

help:
	@echo "[MAKE]: Aegis 2FAuth Importer"
	@echo "  make build  - Build multi-arch image"
	@echo "  make push   - Build and push multi-arch image"
	@echo "  make run    - Run server locally"
	@echo "  make test   - Check Python syntax"
	@echo "  make clean  - Remove local image"

builder:
	@echo "[MAKE]: Setting up Docker Buildx builder"
	@if ! docker buildx inspect $(BUILDER) >/dev/null 2>&1; then \
		docker buildx create --name $(BUILDER) --driver docker-container; \
	fi
	@docker buildx inspect $(BUILDER) --bootstrap
	@echo "[MAKE]: Builder ready"

build: builder
	@echo "[MAKE]: Starting multi-arch build: $(FULL_IMAGE)"
	docker buildx build \
		--builder $(BUILDER) \
		--platform $(PLATFORMS) \
		--tag $(FULL_IMAGE) \
		.
	@echo "[MAKE]: Build finished"

push: builder
	@echo "[MAKE]: Starting multi-arch build and push: $(FULL_IMAGE)"
	docker buildx build \
		--builder $(BUILDER) \
		--platform $(PLATFORMS) \
		--tag $(FULL_IMAGE) \
		--push \
		.
	@echo "[MAKE]: Push finished: $(FULL_IMAGE)"

run:
	@echo "[MAKE]: Starting server"
	docker run --rm -p 5000:5000 $(FULL_IMAGE) \
		python aegis-2fauth-importer.py --serve
	@echo "[MAKE]: Server stopped"

test:
	@echo "[MAKE]: Starting Python syntax check"
	python3 -c "import ast; ast.parse(open('aegis-2fauth-importer.py').read())"
	@echo "[MAKE]: Syntax check finished"

clean:
	@echo "[MAKE]: Removing local image"
	@docker image rm $(FULL_IMAGE) 2>/dev/null || true
	@echo "[MAKE]: Cleanup finished"
