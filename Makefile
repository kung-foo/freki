VERSION := 1.0.2
NAME := freki
GH_PATH := github.com/kung-foo/$(NAME)
BUILDSTRING := $(shell git log --pretty=format:'%h' -n 1)
VERSIONSTRING := $(NAME) version $(VERSION)+$(BUILDSTRING)
OUTPUT = bin/$(NAME)
BUILD_CMD := go build -o $(OUTPUT) -ldflags "-X \"main.VERSION=$(VERSIONSTRING)\"" app/main.go

UID := $(shell id -u)
GID := $(shell id -g)

default: build

$(OUTPUT): glide.lock app/main.go *.go netfilter/*
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
