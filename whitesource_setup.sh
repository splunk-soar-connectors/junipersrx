#!/bin/bash

# cryptography and lxml dependencies
apk add gcc musl-dev python3-dev libffi-dev openssl-dev libxml2-dev libxslt-dev
# need to manually compile a newer version of rust because the version
# available in the alpine base image's repos is too old
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
export PATH="$HOME/.cargo/bin:$PATH"

# only pip2 and pip3 commands work after installing python3-dev, so we overwrite
# the default pip path with a symlink to pip3
ln -fs /usr/bin/pip3 /usr/bin/pip

# Needed by whitesource scripts, gets removed after installing python3-dev
pip3 install requests
