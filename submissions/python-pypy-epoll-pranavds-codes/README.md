# Python on PyPy, raw epoll, no framework

| | |
|---|---|
| Language | Python (3.9 dialect) on **PyPy 7.3.15**, Ubuntu 24.04's `pypy3` package |
| Framework | none: the HTTP/1.1 server is a `select.epoll` loop in `server.py` (one file, ~600 lines with the API) |
| SQLite driver | PyPy's standard-library `sqlite3` (cffi), linked to Ubuntu's SQLite 3.45.1 |
| JSON | built by SQLite (`json_object`), returned as `BLOB` bytes; stdlib `json` only parses request bodies and JWT payloads |
| Third-party packages | **none** (PyPy's bundled cffi calls `accept4()` and OpenSSL's one-shot `HMAC()`) |
| **Nginx or direct** | **Direct**: serves `0.0.0.0:80` itself |

```bash
sudo bash install.sh   # apt: pypy3=7.3.15+dfsg-1build3
bash build.sh          # byte-compiles server.py (nothing to download)
SQLITE_PATH=... JWT_SECRET=... HOST=0.0.0.0 PORT=80 bash start.sh
```

## Results (local, against the fastest Python entries)

Measured in one 4-vCPU Ubuntu 24.04 VM (Intel Xeon @ 2.1 GHz), not the official droplet. Each server is
pinned to **one CPU** (`taskset -c 0`) on a fresh copy of the seed; load generators run on the other three
CPUs over loopback. Compared with [PR #1](https://github.com/arjaythedev/twelve-dollar-server-challenge/pull/1)
(FastAPI), [PR #10](https://github.com/arjaythedev/twelve-dollar-server-challenge/pull/10) (optimized FastAPI)
and [PR #13](https://github.com/arjaythedev/twelve-dollar-server-challenge/pull/13) (Granian RSGI, the fastest Python entry).

### Users, the scored number (`bench/load.js` user model, 60 s ramp + 5-minute hold)

The sandbox caps every process at 20,000 descriptors, so above ~20k users every server must recycle
connections. That is the regime the benchmark box is in above ~65k users (`LimitNOFILE=65535`).

| Users (5-min hold) | PR #13 Granian | This submission |
|---:|---|---|
| 60,000 | PASS: p99 81 ms, 87% CPU, 349 MB | |
| 70,000 | **FAIL**: p99 1,440 ms, 92% CPU | |
| 80,000 | **FAIL**: p99 1,836 ms, 94% CPU | |
| 160,000 | | PASS: p99 296 ms, 81% CPU, 327 MB, 0 errors of 5.07 M |
| 180,000 | | **PASS**: p99 481 ms, 89% CPU, 335 MB, 3 errors of 5.65 M |
| 190,000 | | FAIL: p99 1,067 ms, 92% CPU |

About **2.8× the users** of the fastest Python entry on the same CPU, with a fraction of its memory.
With 60-second holds the picture is the same: Granian passes 80k and fails 100k; this server passes
160k and fails 200k. Official k6 (`bench/load.js`, 4,000 VUs, server descriptor limit
forced to 2,000 so k6 sees constant `Connection: close` recycling) reported 0.00% failed requests,
p95 0.87 ms and p99 2.95 ms.

### Throughput per CPU (wrk, 256 keep-alive connections, medians of 3 interleaved runs)

Mixed workload = bench/load.js's request proportions (100 feed : 100 post : 15 like : 2 create), ids from the newest posts.

| req/s (CPU per request) | PR #1 | PR #10 | PR #13 Granian | This submission |
|---|---:|---:|---:|---:|
| Mixed | 6,056 (164 µs) | 10,365 (96 µs) | 19,849 (50 µs) | **25,353 (39 µs)** |
| `GET /feed` | 5,726 | 8,273 | 11,793 | **14,702** |
| `GET /posts/:id` | 6,783 | 15,142 | 39,551 | **54,763** |
| Mixed, new TCP connection per request | | | 17,366 (57 µs) | **24,460 (41 µs)** |

### Memory

| | PR #13 Granian | This submission |
|---|---:|---:|
| Server memory per idle keep-alive connection (18,000 held) | 10.6 KB | **0.23 KB** |
| RSS under the 160k-user hold | (fails at 70k; 461 MB there) | 327 MB |

Kernel socket memory (~3.9 KB per connection) is the same for every server.

## Where the time goes, and what each change bought

Profiles (`perf`, server CPU only) of the obvious "fast Python" design show the costs this server removes:

1. **No framework, no ASGI/RSGI.** One epoll loop over raw descriptors parses HTTP with `bytes.find`
   and slicing, routes with byte comparisons and writes each response with one `write()`. Pipelining,
   partial reads, partial writes (EPOLLOUT), chunked bodies, `Expect: 100-continue`, HTTP/1.0 and
   `Connection: close` are handled, a request with both `Content-Length` and `Transfer-Encoding` is refused,
   and a client that sends without ever reading is cut off at 1 MB + 16 KB of queued input (`bench/http_edge.py`, 25 checks).
2. **PyPy instead of CPython.** Under CPython this exact server only ties Granian (the interpreter is
   23% of CPU). Under PyPy the JIT shrinks Python to ~10% of CPU: +44% mixed throughput, +45% on
   single posts. What remains is SQLite (~43%) and the kernel's TCP stack (~38%).
3. **SQLite builds the JSON.** `json_object(...)` with `group_concat` and `CAST(... AS BLOB)` returns
   the finished body as bytes: no row tuples, no dicts, no serializer. The feed's 20 rows are taken
   by `LIMIT` in a subquery before the joins; that query is ~20% cheaper than PR #13's form.
4. **Connection recycling instead of a descriptor wall.** With one connection per k6 user, a direct
   server dies at `LimitNOFILE=65535`. Above a keep-alive budget of 25,000 open sockets, replies carry
   `Connection: close` and the socket is closed right after the write. The server closes first, so
   TIME_WAIT stays on the server and the client's port is free again. 25,000 also stays under Linux's
   default ephemeral port range (28,232) if the k6 machine dials from one address. The 65k cap
   becomes a CPU question, and a cheap reconnect makes that question cheap.
5. **Cheap reconnects.** `TCP_DEFER_ACCEPT` makes `accept()` return only once the request bytes have
   arrived. `accept4(SOCK_NONBLOCK)` (cffi) skips two `fcntl`s. The new socket is read and answered
   immediately, and when it is being retired it is closed without ever entering epoll: **4 syscalls**
   per request on a fresh connection (`accept4`, `read`, `write`, `close`), down from 8+.
6. **~230 bytes per connection.** No per-connection objects: a set entry, plus dict entries only
   while a request or reply is partial. Granian holds ~10.6 KB per keep-alive socket.
7. **HMAC via OpenSSL's one-shot `HMAC()`** through cffi into a reused buffer: 1.7 µs instead of
   PyPy's `hmac.digest` at 11.4 µs. PyPy's version also leaked ~2 KB per call until the next major GC
   (anonymous memory grew ~28 MB/s under a like-only load).
8. **`locking_mode=EXCLUSIVE`, `mmap_size=1 GiB`, `synchronous=NORMAL`, autocommit.** A single
   connection owns the database. Each write is its own committed transaction before its 201 (rule 6).
   `foreign_keys=ON` so a validly signed token for a missing user cannot create orphan rows.

Every request runs its own SQL, and every token's signature and `exp`/`nbf` are verified per
request (rule 5). A fast path for the standard `{"alg":"HS256","typ":"JWT"}` header skips
decoding that header (a pure function of its bytes), never the signature check.

### Tried, measured, rejected

| Idea | Result |
|---|---|
| SQLite 3.50.4 / 3.53.4 built with `-O3 -march=native`, `THREADSAFE=0`, `MEMSTATUS=0`, PGO | ~15-20% faster feed query in a microbenchmark, **no measurable end-to-end gain** under PyPy (feed medians 15.4k vs 15.3k vs 15.5k req/s). Not worth a download and compile on the box |
| Background checkpoint thread (`wal_autocheckpoint=0`, second connection) | Slower: −8% mixed throughput, ~4× syscall time per create. On one core the work does not disappear, and it costs exclusive locking |
| Bigger `wal_autocheckpoint` (4,000-16,000 pages) | +13-19% on create-only load, but p99 rose to 96 ms (create-only) and 200 ms (mixed): fewer, bigger stalls. Kept SQLite's 1,000 |
| Granian / uvloop / any ASGI | The framework layer is the cost being removed; see the table above |
| Group commit for likes/creates | Writes are ~8% of requests; savings estimated at under 1% of CPU. Not worth the latency coupling |

### Considered and deliberately not done

- **Coalescing concurrent identical reads** (one feed query answering every `/feed` request in the
  same event-loop batch) would cut SQLite's share several-fold. It shares one query result between
  requests, which reads as a query-result cache under rule 5, so it is left out. Ask the maintainer first.
- **A hand-written C extension** for the hot loop would be faster still, but then it is a C submission.

## Caveats

- Loopback benchmarking charges the client's TCP receive path to the server CPU (about 20% of the
  server's kernel time in the profiles) and hides NIC/interrupt costs. Absolute numbers on the droplet will
  differ; the ratios between servers are what these tables show.
- The sandbox's 20,000-descriptor limit forced more recycling than the droplet will (budget 19,744
  here, 25,000 there), which penalizes Granian as well. Its own budget is 40,000 descriptors at ~10.6 KB each.
- A JWT without `exp` is accepted, as by jsonwebtoken, PyJWT and golang-jwt. PR #13's stricter
  extra checks flag that one case; every other one of its 78 HTTP checks plus 16 concurrent likes passes.
- PyPy RSS starts at ~200 MB (JIT and GC nursery) and stayed flat over the 5-minute holds.

## Reproducing

```bash
bash seed/make-seed.sh
bash test/run.sh submissions/python-pypy-epoll-pranavds-codes                 # 42/42
cd submissions/python-pypy-epoll-pranavds-codes
bench/throughput.sh . mix 256 10            # needs wrk; CLOSE=close for a connection per request
bench/capacity.sh . 160000 300 60           # user model; needs cc; shards of 16k users
python3 bench/http_edge.py 3100 "$TOKEN"    # against a running server on a fresh seed copy
```

## Credits

[PR #13](https://github.com/arjaythedev/twelve-dollar-server-challenge/pull/13) (tbsvttr) introduced
SQLite-built JSON bytes and descriptor-pressure retirement for Python, and wrote `bench/connection_load.c`
(copied unchanged, MIT). [PR #1](https://github.com/arjaythedev/twelve-dollar-server-challenge/pull/1)
(cknutson12) and [PR #10](https://github.com/arjaythedev/twelve-dollar-server-challenge/pull/10)
(tejasnafde) set the SQL and the "skip the framework" direction.

MIT, under the repo's [license](../../LICENSE).
