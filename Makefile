all:
	make init
	make build

init:
	go get ./...
	go generate -x ./server/...

# Max text-file size (in MB) that the built-in editor will open. Files larger
# than this are routed to the downloader view instead. Override at build time:
#   make build EDITOR_MAX_SIZE_MB=500
EDITOR_MAX_SIZE_MB ?= 100

build:
	go build --tags "fts5" \
		-ldflags "-X github.com/mickael-kerjean/filestash/server/common.EDITOR_MAX_SIZE_MB=$(EDITOR_MAX_SIZE_MB)" \
		-o dist/filestash$(if $(filter windows,$(GOOS)),.exe) cmd/main.go
