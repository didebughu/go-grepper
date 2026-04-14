.PHONY: build clean test run

# 版本信息
# VERSION ?= 3.0.0-dev
BINARY_NAME = go-grepper
BUILD_DIR = bin

# Go 编译参数
# LDFLAGS = -ldflags "-X main.version=$(VERSION)"

build:
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/go-grepper/

clean:
	rm -rf $(BUILD_DIR)

test:
	go test ./...

run: build
	./$(BUILD_DIR)/$(BINARY_NAME) scan -t . -l cpp -v

# 交叉编译
build-all:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/go-grepper/
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/go-grepper/
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/go-grepper/
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/go-grepper/

lint:
	golangci-lint run ./...
