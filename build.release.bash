#!/bin/bash

#
# SaltedAuth Remote Installation Script
# This script installs the module to the server when updates are released.
# Only works on AutoRelease enabled repository services.
#
# Also, it needs the autorelease.allow.install file on the server.
#

function prepare() {
	destination "/etc/connective-http/"
	buildOutput "build/libs/"
}

function build() {
    chmod +x gradlew
    ./gradlew build
}

function install() {
	cp -rfv "$BUILDDIR/"SaltedAuth-*.jar "$DEST/modules"
	cp -rfv .credtool.target "/etc/connective-http/"
}

function postInstall() {
    log Rebooting HTTP server...
	systemctl restart connective-http
}
