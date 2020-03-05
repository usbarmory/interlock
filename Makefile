SHELL = /bin/bash
GO ?= go
BUILD_TAGS = ""
BUILD_USER = $(shell whoami)
BUILD_HOST = $(shell hostname)
BUILD_DATE = $(shell /bin/date -u "+%Y-%m-%d %H:%M:%S")
BUILD = ${BUILD_USER}@${BUILD_HOST} on ${BUILD_DATE}
REV = $(shell git rev-parse --short HEAD 2> /dev/null)
PKG = "github.com/f-secure-foundry/interlock"

all: build

build:
	$(GO) build -v -tags ${BUILD_TAGS} \
	  -gcflags=-trimpath=${CURDIR} -asmflags=-trimpath=${CURDIR} \
	  -ldflags "-s -w -X '${PKG}/internal.Build=${BUILD} ${BUILD_TAGS}' -X '${PKG}/internal.Revision=${REV}'" \
	  interlock.go
	@echo "compiled INTERLOCK ${REV} (${BUILD})"
