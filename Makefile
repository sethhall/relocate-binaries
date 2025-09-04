.PHONY: build test clean

build:
	go build -o relocate-binaries main.go

test:
	go test -v ./...

clean:
	rm -rf relocate-binaries output test_output || true
