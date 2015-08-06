#!/bin/bash

GO ?= go
BUILD_GOPATH = $(CURDIR)
BUILD_TAGS = ""
BUILD_USER = $(shell whoami)
BUILD_HOST = $(shell hostname)
BUILD_DATE = $(shell /bin/date -u "+%Y-%m-%d %H:%M:%S")
BUILD = "${BUILD_USER}@${BUILD_HOST} on ${BUILD_DATE}"

all: build

build:
	cd src && GOPATH="${BUILD_GOPATH}" $(GO) build -tags ${BUILD_TAGS} -ldflags "-X main.InterlockBuild \"${BUILD_USER}@${BUILD_HOST} on ${BUILD_DATE} +${BUILD_TAGS}\"" -o ../interlock

with_textsecure: BUILD_GOPATH = "$(CURDIR):${GOPATH}"
with_textsecure: BUILD_TAGS = "textsecure"
with_textsecure: build
