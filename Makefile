
default: build

build:
	@mkdir -p bin/
	go build -o bin/freki app/main.go

clean:
	rm -rf bin/
