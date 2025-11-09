#!/bin/bash

echo "Building Android..."
cargo ndk -t armeabi-v7a -t arm64-v8a -t x86 -t x86_64 -o ./jniLibs build --release

echo "Building iOS..."
cargo lipo --release

echo "Building Web..."
wasm-pack build --target web -d ../../web/src/argon2_wasm

echo "Building Desktop..."
cargo build --release
