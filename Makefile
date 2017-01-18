VERSION := 1.0.0
BUILDSTRING := $(shell git log --pretty=format:'%h' -n 1)
VERSIONSTRING := freki version $(VERSION)+$(BUILDSTRING)

default: build

OUTPUT = bin/freki

$(OUTPUT): glide.lock app/main.go *.go netfilter/*
	@mkdir -p bin/
	go build -o $(OUTPUT) -ldflags "-X \"main.VERSION=$(VERSIONSTRING)\"" app/main.go

build: $(OUTPUT)

upx: build
	upx -1 bin/freki

clean:
	rm -rf bin/
