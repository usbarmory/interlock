#!/bin/bash

GO ?= go

all: build

build:
	cd server && $(GO) build -o ../interlock
