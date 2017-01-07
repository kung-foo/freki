
default: build

build:
	@mkdir -p bin/
	go build -o bin/freki app/main.go
	upx -1 bin/freki

clean:
	rm -rf bin/
