VERSION := 1.1.1
NAME := freki
GH_PATH := github.com/kung-foo/$(NAME)
BUILDSTRING := $(shell git log --pretty=format:'%h' -n 1)
VERSIONSTRING := $(NAME) version $(VERSION)+$(BUILDSTRING)
OUTPUT = bin/$(NAME)
BUILD_CMD := go build -o $(OUTPUT) -ldflags "-X \"main.VERSION=$(VERSIONSTRING)\"" app/main.go

UID := $(shell id -u)
GID := $(shell id -g)

default: build

$(OUTPUT): go.sum app/main.go *.go netfilter/*
	@mkdir -p bin/
	$(BUILD_CMD)

build: $(OUTPUT)

upx: build
	upx -1 $(OUTPUT)

clean:
	rm -rf bin/*

DOCKER_OPTS := -v "$(PWD)":/go/src/$(GH_PATH) -w /go/src/$(GH_PATH)

ALPINE_TAG := $(NAME)-build:alpine
build-docker-alpine:
	docker build -t $(ALPINE_TAG) -f Dockerfile.alpine .
	docker run --rm -u $(UID):$(GID) $(DOCKER_OPTS) $(ALPINE_TAG) $(BUILD_CMD)
	mv $(OUTPUT) $(OUTPUT)-musl

build-docker-alpine-sh:
	docker run --rm -it $(DOCKER_OPTS) $(ALPINE_TAG) ash

DEBIAN_TAG := $(NAME)-build:debian
build-docker-debian:
	docker build -t $(DEBIAN_TAG) -f Dockerfile.debian .
	docker run --rm -u $(UID):$(GID) $(DOCKER_OPTS) $(DEBIAN_TAG) $(BUILD_CMD)

build-docker-debian-sh:
	docker run --rm -it $(DOCKER_OPTS) $(DEBIAN_TAG) bash

RUN_DC := docker-compose -f system_test/docker-compose.yml
system-test:
	$(RUN_DC) up --build --abort-on-container-exit
	$(RUN_DC) ps -q | xargs docker inspect -f '{{ .State.ExitCode }}' | grep -v 0 | wc -l | tr -d ' ' > /tmp/dc-exit-code.txt
	$(RUN_DC) rm -f -v freki test
	@echo 'Exit code: '`cat /tmp/dc-exit-code.txt`
	@exit `cat /tmp/dc-exit-code.txt`
