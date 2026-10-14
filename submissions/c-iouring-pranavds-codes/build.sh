#!/usr/bin/env bash
# Builds bin/server as a normal user. Downloads the pinned SQLite amalgamation (SHA-256 checked) unless
# deps/sqlite3.c is already there, builds SQLite with profile-guided optimization trained on a
# synthetic database (pgo/train.c; no seed data), then the server.
set -euo pipefail
cd "$(dirname "$0")"
SQLITE=sqlite-autoconf-3530400
SQLITE_SHA256=0e9483900e92cd5de8fd48d16bf9200145a61f7fd5be542a5ac81d8a9516eb9c
mkdir -p deps build bin
if [ ! -f deps/sqlite3.c ]; then
  curl -fsSL --retry 3 -o deps/sqlite.tar.gz "https://www.sqlite.org/2026/$SQLITE.tar.gz"
  echo "$SQLITE_SHA256  deps/sqlite.tar.gz" | sha256sum -c --quiet -
  tar -xzf deps/sqlite.tar.gz -C deps --strip-components=1 "$SQLITE/sqlite3.c" "$SQLITE/sqlite3.h"
  rm deps/sqlite.tar.gz
fi
CFLAGS=(-O3 -march=native -fno-plt -g0)
SQLITE_OPTS=(-DSQLITE_THREADSAFE=0 -DSQLITE_DEFAULT_MEMSTATUS=0 -DSQLITE_DEFAULT_WAL_SYNCHRONOUS=1
  -DSQLITE_DQS=0 -DSQLITE_LIKE_DOESNT_MATCH_BLOBS -DSQLITE_MAX_EXPR_DEPTH=0 -DSQLITE_OMIT_DEPRECATED
  -DSQLITE_OMIT_PROGRESS_CALLBACK -DSQLITE_OMIT_SHARED_CACHE -DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_USE_ALLOCA)
PROFILE="$PWD/build/pgo"
rm -rf "$PROFILE"
# 1. instrumented SQLite + training run on a synthetic database
gcc "${CFLAGS[@]}" "${SQLITE_OPTS[@]}" -w -fprofile-generate -fprofile-update=single -fprofile-dir="$PROFILE" \
  -Ideps -c deps/sqlite3.c -o build/sqlite3-gen.o
gcc "${CFLAGS[@]}" -Ideps -fprofile-generate -fprofile-dir="$PROFILE" pgo/train.c build/sqlite3-gen.o -lm -o build/train
(cd build && ./train)
# 2. optimized SQLite from the profile
gcc "${CFLAGS[@]}" "${SQLITE_OPTS[@]}" -w -fprofile-use -fprofile-partial-training -fprofile-correction \
  -Wno-missing-profile -fprofile-dir="$PROFILE" -Ideps -c deps/sqlite3.c -o build/sqlite3.o
# 3. the server
gcc "${CFLAGS[@]}" -std=gnu11 -Wall -Wextra -Wno-deprecated-declarations -Ideps server.c build/sqlite3.o \
  -luring -lcrypto -lm -o bin/server
echo "built bin/server"
