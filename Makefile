SHELL = /bin/bash
GO ?= go
GO_VERSION = $(shell ${GO} version | cut -d' ' -f 3)
BUILD_GOPATH = $(CURDIR)
BUILD_TAGS = ""
BUILD_USER = $(shell whoami)
BUILD_HOST = $(shell hostname)
BUILD_DATE = $(shell /bin/date -u "+%Y-%m-%d %H:%M:%S")
BUILD = ${BUILD_USER}@${BUILD_HOST} on ${BUILD_DATE}
REV = $(shell git rev-parse --short HEAD 2> /dev/null)
PKGPATH = "github.com/inversepath/interlock"

all: build

build:
	@echo "compiling INTERLOCK ${REV} (${BUILD} with ${GO_VERSION})"
	$(GO) build -v -tags ${BUILD_TAGS} \
	  -ldflags "-s -w -X '${PKGPATH}/internal.Build=${BUILD} ${BUILD_TAGS}' -X '${PKGPATH}/internal.Revision=${REV}'" \
	  cmd/interlock.go
	@echo "done compiling INTERLOCK"

with_signal: BUILD_GOPATH = "$(CURDIR):${GOPATH}"
with_signal: BUILD_TAGS = "signal"
with_signal: build
