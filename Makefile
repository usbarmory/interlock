#!/bin/bash

SHELL = /bin/bash
GO ?= go
GO_VERSION = $(shell ${GO} version)
BUILD_GOPATH = $(CURDIR)
BUILD_TAGS = ""
BUILD_USER = $(shell whoami)
BUILD_HOST = $(shell hostname)
BUILD_DATE = $(shell /bin/date -u "+%Y-%m-%d %H:%M:%S")
BUILD = "${BUILD_USER}@${BUILD_HOST} on ${BUILD_DATE}"

all: build

build:
	@echo "compiling INTERLOCK with ${GO_VERSION}"
	@if test "$(shell echo "${GO_VERSION} go1.5" | sort -V | tail -n 1 | cut -d' ' -f 3)" == "go1.5"; then \
		echo "detected go version >= 1.5"; \
		cd src && GOPATH="${BUILD_GOPATH}" $(GO) build -v -tags ${BUILD_TAGS} -ldflags "-X 'main.InterlockBuild=${BUILD_USER}@${BUILD_HOST} on ${BUILD_DATE} ${BUILD_TAGS}'" -o ../interlock; \
	else \
		echo "detected go version < 1.5"; \
		cd src && GOPATH="${BUILD_GOPATH}" $(GO) build -v -tags ${BUILD_TAGS} -ldflags "-X main.InterlockBuild \"${BUILD_USER}@${BUILD_HOST} on ${BUILD_DATE} ${BUILD_TAGS}\"" -o ../interlock; \
	fi
	@echo "done compiling INTERLOCK"

with_textsecure: BUILD_GOPATH = "$(CURDIR):${GOPATH}"
with_textsecure: BUILD_TAGS = "textsecure"
with_textsecure: build
