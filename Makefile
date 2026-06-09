
TAG := $(shell cat image/tag)
DEPS := image/entrypoint.sh image/requirements.txt src/cert_manager.py

all: cert-manager

cert-manager: image/Dockerfile $(DEPS)
	docker build -f image/Dockerfile -t cert-manager:$(TAG) .

pynstaller: image/Dockerfile.pynstaller $(DEPS)
	docker build -f image/Dockerfile.pynstaller -t cert-manager:$(TAG)-pynstaller .

nuitka: image/Dockerfile.nuitka $(DEPS)
	docker build -f image/Dockerfile.nuitka -t cert-manager:$(TAG)-nuitka .