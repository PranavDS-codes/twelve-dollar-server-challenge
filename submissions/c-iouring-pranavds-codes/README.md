# C + io_uring, one thread

| | |
|---|---|
| Language | C (GNU C11), Ubuntu 24.04's GCC 13, `-O3 -march=native` |
| Framework | none: one thread drives one io_uring (liburing 2.5 from apt) |
| SQLite | 3.53.4 amalgamation (SHA-256 pinned), built with profile-guided optimization trained on a synthetic database |
| JWT | OpenSSL SHA-256 with the HMAC key pads hashed once at start-up |
| **Nginx or direct** | **Direct**: serves `0.0.0.0:80` itself |

```bash
sudo bash install.sh   # build-essential, liburing-dev, libssl-dev
bash build.sh          # SQLite PGO build + server, about 1.5 minutes
SQLITE_PATH=... JWT_SECRET=... HOST=0.0.0.0 PORT=80 bash start.sh
```

## Design

- **One thread, one ring.** Multishot accept straight into the ring's registered (fixed) file table,
  multishot recv from a provided-buffer ring, and every reply of a loop pass handed to the kernel in one
  `io_uring_enter`. When busy, the loop waits for 64 completions or 1 ms.
- **Keep-alive budget instead of a descriptor wall.** A connection accepted while 26,000 are open serves
  one request: it gets a single-shot recv, its reply carries `Connection: close`, and the reply's send is
  linked to the close in the same submission (`MSG_WAITALL`, `IOSQE_IO_LINK`). The server closes first,
  so the client keeps no TIME_WAIT and its ephemeral port is free again; 26,000 stays under Linux's
  default port range for a single-address load generator. Users are then bounded by CPU, not by
  `LimitNOFILE`, kernel memory or the generator's ports.
- **No cancel scans.** `IORING_OP_ASYNC_CANCEL` by fd walks every in-flight request, which is quadratic
  with tens of thousands of armed recvs (70% of CPU at 40k users in an earlier version). A still-armed
  recv is ended with `shutdown()` instead.
- **Group commit and one read transaction per pass.** Requests of one loop pass share a transaction:
  writes are one commit, reads skip per-statement transaction setup, and no reply of the pass is sent
  before the commit (rule 6). A failed commit turns that pass's replies into 500s.
- **Short WAL.** `wal_autocheckpoint=0` and a passive checkpoint after the commit that takes the WAL to
  1,000 frames. At 4,000 frames `walFindFrame` (run for every page read) was 11% of CPU.
- **Feed as three range scans.** Read the 20 newest ids from the `(created_at, id)` index; when they span
  fewer than 256 ids (new posts get adjacent ids), read the rows with one `BETWEEN` scan of
  `posts JOIN users` and count likes with one scan of `likes_post_id_idx`, then emit in feed order.
  Otherwise, or if a row is missing, the reference query runs.
- **Cheap JSON.** Replies are written straight into the send buffer; strings are escaped eight bytes at a
  time while none needs escaping. Idle connections hold no buffers (about 60 bytes each).

Every request runs its own SQL and every token's signature and `exp`/`nbf` are verified per request
(rule 5). A JWT without `exp` is accepted, as by jsonwebtoken, PyJWT and golang-jwt.

HTTP hardening: a request carrying both `Content-Length` and `Transfer-Encoding`, or a transfer coding
other than `chunked`, gets 400; `Connection` is read as a token list (`TE, close` closes); a client that
pipelines without reading is dropped once 8 MB of replies are queued for it.

## Local results

One pinned core of a 2.1 GHz Xeon VM, load from the other three cores over loopback, fresh seed copy.
Users: PR #13's C load generator replays the `bench/load.js` loop per user; steps of 10k, 20k, 40k, 80k,
120k, 160k, 200k, 240k users, each on a fresh database with a 20 s warm-up, 15 s ramp and 45 s hold, passing
with p95 < 500 ms, p99 < 1 s and < 1% errors. Every server in the table went through the same runs.

| | Mixed req/s (load.js ratio, 256 keep-alive) | CPU µs/request | Users (load.js loop, 45 s hold) |
|---|---:|---:|---:|
| This server | 78,000–86,000 | 11.4–12.5 | **≥ 240,000** (p99 31 ms, 69% CPU, 72 MB RSS; 240k is the load generator's ceiling here) |
| Zig uSockets, PR #25 | 50,700 | 19.4 | 200,000 (fails at 220k) |
| C++ EASTL io_uring, PR #32 | 81,000–83,000 | 11.7–11.9 | 180,000 (fails at 200k) |
| Rust io_uring, PR #19 | 82,000–88,000 | 11.1–11.8 | 140,000 (fails at 160k) |
| C io_uring, PR #26 | 78,600 | 12.4 | 140,000 (fails at 160k) |

Official profile (`bench/load.js` loop, 60 s ramp, 5-minute hold): **240,000 users pass** with p95 19 ms,
p99 52 ms, 427 errors in 7,615,790 requests (0.006%), 69% server CPU and 116 MB peak RSS.

Tests: 42/42 official, 25 raw-socket HTTP edge cases (pipelining, partial reads and writes, chunked
bodies, `Expect: 100-continue`, HTTP/1.0), and PR #13's 78 extra checks plus 16 concurrent likes.

## Credits

The feed range scans, exclusive locking and explicit checkpoints follow C #26 (raoz), Rust #19
(scooter1337) and C++ #32 (hendy643); the keep-alive budget and `TCP_DEFER_ACCEPT` come from this
fork's Python entry, `python-pypy-epoll-pranavds-codes`.

MIT, under the repo's [license](../../LICENSE).
