.PHONY: build

build:
	go build -o relocate-binaries main.go
	(command -v clang >/dev/null && clang -static -Os -ffunction-sections -fdata-sections -Wl,--gc-sections -Wall -Wextra -Werror -o wrapper wrapper.c && strip wrapper) || (command -v gcc >/dev/null && gcc -static -Os -ffunction-sections -fdata-sections -Wl,--gc-sections -Wall -Wextra -Werror -o wrapper wrapper.c && strip wrapper) || (echo "Neither clang nor gcc found" && exit 1)
