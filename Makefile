#!/bin/bash

GO ?= go
BUILD_USER = $(shell whoami)
BUILD_HOST = $(shell hostname)
BUILD_DATE = $(shell /bin/date -u +%Y/%m/%d-%H:%M:%S)

all: build

build:
	cd server && $(GO) build -ldflags "-X main.InterlockBuild \"${BUILD_USER}@${BUILD_HOST} on ${BUILD_DATE}\"" -o ../interlock
