/* The $12 server challenge API in C: one thread, io_uring, SQLite in-process.
 *
 *  - io_uring: multishot accept straight into the ring's registered (fixed) file table, multishot recv
 *    from a provided-buffer ring, every reply of a loop pass handed to the kernel in one io_uring_enter.
 *  - Keep-alive budget: connections accepted while more than KEEPALIVE_BUDGET are open serve one
 *    request, get "Connection: close", and are closed by a send->close link (server closes first, so the
 *    client keeps no TIME_WAIT and its port is free again). The user count is then bounded by CPU, not by
 *    descriptors, memory or the load generator's ephemeral ports.
 *  - Closing never uses IORING_OP_ASYNC_CANCEL (cancel-by-fd scans every in-flight request: quadratic
 *    with tens of thousands of armed recvs); a still-armed recv is ended by shutdown().
 *  - SQLite: one connection, WAL + synchronous=NORMAL, exclusive locking, checkpoints every 1,000 WAL
 *    frames. Every request runs its own statements; the requests of one loop pass share one
 *    transaction, so its writes are one group commit and no reply of the pass is sent before it.
 *  - The feed reads the 20 newest ids, then (when they are close together, as they are in practice)
 *    one range scan of posts+users and one of the likes index instead of 20 + 20 point lookups.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <liburing.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/sha.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

/* ------------------------------------------------------------------------------------------------ */
/* Tunables                                                                                          */

#define MAX_RINGS 1              /* one ring: its fixed table (<= RLIMIT_NOFILE, <= 65535) holds every
                                    socket, since the keep-alive budget stays below it                   */
#define SQ_ENTRIES 4096
#define CQ_ENTRIES 32768
#define BUF_COUNT 4096           /* provided receive buffers per ring                               */
#define BUF_SIZE 4096
#define BATCH_WAIT 64            /* when busy, wait for this many completions ...                    */
#define BATCH_USEC 1000          /* ... or this long                                                 */
#define MAX_HEAD 16384
#define MAX_BODY (1 << 20)
#define MAX_PENDING_OUT (8u << 20) /* unsent replies past this: the client is not reading, drop it */
#define IDLE_SECONDS 180         /* connections idle this long are closed (sweep every 15 s)         */
/* Keep-alive budget. A connection accepted while this many are open serves one request: its reply
 * carries "Connection: close" and the server closes right after sending, so its slot is free again.
 * The server closes first, so the client's port is released at once (TIME_WAIT stays here). 26,000
 * keeps a single-address load generator under Linux's default ephemeral port range (28,232 ports from
 * one address to one ip:port); kernel memory (~4.5 KB per socket) is not the limit. It is lowered at
 * start-up if the fixed table (RLIMIT_NOFILE) could not also hold the one-request connections in flight. */
static unsigned KEEPALIVE_BUDGET = 26000;

/* ------------------------------------------------------------------------------------------------ */
/* Small helpers                                                                                     */

static void die(const char *what) { perror(what); exit(1); }

typedef struct { char *p; uint32_t len, cap; } buf_t;

static void buf_reserve(buf_t *b, uint32_t extra)
{
    if (likely(b->len + extra <= b->cap)) return;
    uint32_t cap = b->cap ? b->cap : 1024;
    while (cap < b->len + extra) cap *= 2;
    b->p = realloc(b->p, cap);
    if (!b->p) die("realloc");
    b->cap = cap;
}
static inline void buf_put(buf_t *b, const void *s, uint32_t n)
{
    buf_reserve(b, n);
    memcpy(b->p + b->len, s, n);
    b->len += n;
}
#define buf_lit(b, s) buf_put((b), (s), sizeof(s) - 1)
static inline void buf_u64(buf_t *b, uint64_t v)
{
    char tmp[24];
    int i = 24;
    do { tmp[--i] = (char)('0' + v % 10); v /= 10; } while (v);
    buf_put(b, tmp + i, (uint32_t)(24 - i));
}
static void buf_free(buf_t *b) { free(b->p); b->p = NULL; b->len = b->cap = 0; }

/* JSON string body, escaped like JSON.stringify (raw UTF-8 passes through). Eight bytes at a time while
 * none of them needs escaping (no control byte, '"' or '\\'). */
static inline int clean8(uint64_t v)
{
    const uint64_t ones = 0x0101010101010101ULL, high = 0x8080808080808080ULL;
    uint64_t ctrl = (v - ones * 0x20) & ~v;          /* bytes < 0x20 */
    uint64_t q = v ^ (ones * '"'), b = v ^ (ones * '\\');
    uint64_t zq = (q - ones) & ~q, zb = (b - ones) & ~b;
    return !((ctrl | zq | zb) & high);
}
static inline char *json_str_raw(char *o, const unsigned char *s, int n)
{
    *o++ = '"';
    int i = 0;
    for (; i + 8 <= n; i += 8) {
        uint64_t v;
        memcpy(&v, s + i, 8);
        if (likely(clean8(v))) { memcpy(o, &v, 8); o += 8; continue; }
        break;
    }
    for (; i < n; i++) {
        unsigned char c = s[i];
        if (likely(c >= 0x20 && c != '"' && c != '\\')) { *o++ = (char)c; continue; }
        *o++ = '\\';
        switch (c) {
        case '"': *o++ = '"'; break;
        case '\\': *o++ = '\\'; break;
        case '\b': *o++ = 'b'; break;
        case '\f': *o++ = 'f'; break;
        case '\n': *o++ = 'n'; break;
        case '\r': *o++ = 'r'; break;
        case '\t': *o++ = 't'; break;
        default:
            *o++ = 'u'; *o++ = '0'; *o++ = '0';
            *o++ = "0123456789abcdef"[c >> 4]; *o++ = "0123456789abcdef"[c & 15];
        }
    }
    *o++ = '"';
    return o;
}
static void buf_json_str(buf_t *b, const unsigned char *s, int n)
{
    buf_reserve(b, (uint32_t)n * 6 + 2);
    b->len = (uint32_t)(json_str_raw(b->p + b->len, s, n) - b->p);
}
static inline char *u64_raw(char *o, uint64_t v)
{
    char tmp[24];
    int i = 24;
    do { tmp[--i] = (char)('0' + v % 10); v /= 10; } while (v);
    memcpy(o, tmp + i, (size_t)(24 - i));
    return o + (24 - i);
}

/* ------------------------------------------------------------------------------------------------ */
/* HTTP responses                                                                                    */

static char date_hdr[64];      /* "Date: ...\r\n" */
static int date_len;
static time_t date_sec;
static uint32_t now_sec;       /* monotonic seconds, for idle sweeps */

static void refresh_clock(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
    now_sec = (uint32_t)ts.tv_sec;
    time_t t = time(NULL);
    if (t == date_sec) return;
    date_sec = t;
    struct tm tm;
    gmtime_r(&t, &tm);
    date_len = (int)strftime(date_hdr, sizeof date_hdr, "Date: %a, %d %b %Y %H:%M:%S GMT\r\n", &tm);
}

static const char *status_line(int status)
{
    switch (status) {
    case 200: return "HTTP/1.1 200 OK\r\n";
    case 201: return "HTTP/1.1 201 Created\r\n";
    case 400: return "HTTP/1.1 400 Bad Request\r\n";
    case 401: return "HTTP/1.1 401 Unauthorized\r\n";
    case 404: return "HTTP/1.1 404 Not Found\r\n";
    case 413: return "HTTP/1.1 413 Payload Too Large\r\n";
    case 431: return "HTTP/1.1 431 Request Header Fields Too Large\r\n";
    case 503: return "HTTP/1.1 503 Service Unavailable\r\n";
    default: return "HTTP/1.1 500 Internal Server Error\r\n";
    }
}

/* Writes the head with a fixed-width Content-Length placeholder; returns the offset to patch. */
static uint32_t head_begin(buf_t *out, int status, int close)
{
    const char *sl = status_line(status);
    buf_put(out, sl, (uint32_t)strlen(sl));
    buf_lit(out, "Content-Type: application/json\r\n");
    buf_put(out, date_hdr, (uint32_t)date_len);
    if (close) buf_lit(out, "Connection: close\r\n");
    buf_lit(out, "Content-Length: ");
    uint32_t at = out->len;
    buf_lit(out, "       \r\n\r\n"); /* 7 digits: bodies are far smaller than 10 MB */
    return at;
}
static void head_end(buf_t *out, uint32_t at)
{
    uint32_t body = out->len - (at + 11);
    char *p = out->p + at;
    int digits = 1;
    for (uint32_t v = body; v >= 10; v /= 10) digits++;
    /* right-trim: write digits, then move "\r\n\r\n" + body left over the unused spaces */
    char tmp[8];
    for (int i = digits - 1; i >= 0; i--) { tmp[i] = (char)('0' + body % 10); body /= 10; }
    memcpy(p, tmp, (size_t)digits);
    uint32_t gap = 7 - (uint32_t)digits;
    if (gap) {
        memmove(p + digits, p + 7, out->len - (at + 7));
        out->len -= gap;
    }
}
static void respond_raw(buf_t *out, int status, int close, const char *body, uint32_t n)
{
    uint32_t at = head_begin(out, status, close);
    buf_put(out, body, n);
    head_end(out, at);
}
#define respond_lit(out, status, close, lit) respond_raw((out), (status), (close), (lit), sizeof(lit) - 1)

#define E_NOT_FOUND "{\"error\":\"not found\"}"
#define E_BAD_ID "{\"error\":\"invalid post id\"}"
#define E_NO_POST "{\"error\":\"post not found\"}"
#define E_NO_TOKEN "{\"error\":\"missing bearer token\"}"
#define E_BAD_TOKEN "{\"error\":\"invalid or expired token\"}"
#define E_BAD_PAYLOAD "{\"error\":\"invalid token payload\"}"
#define E_BAD_JSON "{\"error\":\"malformed JSON body\"}"
#define E_NO_BODY "{\"error\":\"body is required\"}"
#define E_LONG_BODY "{\"error\":\"body must be at most 500 characters\"}"
#define E_INTERNAL "{\"error\":\"internal server error\"}"
#define E_BAD_REQUEST "{\"error\":\"bad request\"}"
#define E_HEAD_TOO_LARGE "{\"error\":\"request header fields too large\"}"
#define E_TOO_LARGE "{\"error\":\"payload too large\"}"

/* ------------------------------------------------------------------------------------------------ */
/* Strict JSON (RFC 8259) for request bodies and JWT segments                                        */

/* Validates one UTF-8 sequence at s (n bytes left). Returns its length, or 0 if invalid. */
static int utf8_len(const unsigned char *s, size_t n, uint32_t *cp)
{
    unsigned char c = s[0];
    if (c < 0x80) { *cp = c; return 1; }
    if (c < 0xC2) return 0;
    if (c < 0xE0) {
        if (n < 2 || (s[1] & 0xC0) != 0x80) return 0;
        *cp = ((uint32_t)(c & 0x1F) << 6) | (s[1] & 0x3F);
        return 2;
    }
    if (c < 0xF0) {
        if (n < 3 || (s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80) return 0;
        uint32_t v = ((uint32_t)(c & 0x0F) << 12) | ((uint32_t)(s[1] & 0x3F) << 6) | (s[2] & 0x3F);
        if (v < 0x800 || (v >= 0xD800 && v <= 0xDFFF)) return 0;
        *cp = v;
        return 3;
    }
    if (c < 0xF5) {
        if (n < 4 || (s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80 || (s[3] & 0xC0) != 0x80) return 0;
        uint32_t v = ((uint32_t)(c & 0x07) << 18) | ((uint32_t)(s[1] & 0x3F) << 12) |
                     ((uint32_t)(s[2] & 0x3F) << 6) | (s[3] & 0x3F);
        if (v < 0x10000 || v > 0x10FFFF) return 0;
        *cp = v;
        return 4;
    }
    return 0;
}
static int put_utf8(char *o, uint32_t cp)
{
    if (cp < 0x80) { o[0] = (char)cp; return 1; }
    if (cp < 0x800) { o[0] = (char)(0xC0 | (cp >> 6)); o[1] = (char)(0x80 | (cp & 0x3F)); return 2; }
    if (cp < 0x10000) {
        o[0] = (char)(0xE0 | (cp >> 12)); o[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        o[2] = (char)(0x80 | (cp & 0x3F));
        return 3;
    }
    o[0] = (char)(0xF0 | (cp >> 18)); o[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
    o[2] = (char)(0x80 | ((cp >> 6) & 0x3F)); o[3] = (char)(0x80 | (cp & 0x3F));
    return 4;
}

typedef struct { const unsigned char *p, *e; } jp_t;

static inline void jp_ws(jp_t *j)
{
    while (j->p < j->e && (*j->p == ' ' || *j->p == '\t' || *j->p == '\n' || *j->p == '\r')) j->p++;
}
static int hex4(const unsigned char *p, uint32_t *v)
{
    uint32_t r = 0;
    for (int i = 0; i < 4; i++) {
        unsigned char c = p[i];
        r <<= 4;
        if (c >= '0' && c <= '9') r |= (uint32_t)(c - '0');
        else if ((c | 0x20) >= 'a' && (c | 0x20) <= 'f') r |= (uint32_t)((c | 0x20) - 'a' + 10);
        else return 0;
    }
    *v = r;
    return 1;
}
/* Parses a string at j->p (which is '"'). If out is non-NULL, the decoded UTF-8 goes there (it must
 * have room for the raw length) and *outlen gets its length. Returns 0 on malformed input. */
static int jp_string(jp_t *j, char *out, size_t *outlen)
{
    const unsigned char *p = j->p + 1, *e = j->e;
    char *o = out;
    while (p < e) {
        unsigned char c = *p;
        if (c == '"') {
            j->p = p + 1;
            if (out) *outlen = (size_t)(o - out);
            return 1;
        }
        if (c < 0x20) return 0;
        if (c == '\\') {
            if (p + 1 >= e) return 0;
            unsigned char x = p[1];
            uint32_t cp;
            p += 2;
            switch (x) {
            case '"': cp = '"'; break;
            case '\\': cp = '\\'; break;
            case '/': cp = '/'; break;
            case 'b': cp = '\b'; break;
            case 'f': cp = '\f'; break;
            case 'n': cp = '\n'; break;
            case 'r': cp = '\r'; break;
            case 't': cp = '\t'; break;
            case 'u':
                if (e - p < 4 || !hex4(p, &cp)) return 0;
                p += 4;
                if (cp >= 0xD800 && cp <= 0xDBFF) { /* needs a low surrogate */
                    uint32_t lo;
                    if (e - p < 6 || p[0] != '\\' || p[1] != 'u' || !hex4(p + 2, &lo) || lo < 0xDC00 || lo > 0xDFFF)
                        return 0;
                    p += 6;
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                } else if (cp >= 0xDC00 && cp <= 0xDFFF) return 0; /* lone surrogate */
                break;
            default: return 0;
            }
            if (o) o += put_utf8(o, cp);
            continue;
        }
        uint32_t cp;
        int n = utf8_len(p, (size_t)(e - p), &cp);
        if (!n) return 0;
        if (o) { memcpy(o, p, (size_t)n); o += n; }
        p += n;
    }
    return 0;
}
/* Number per RFC 8259; *out gets its value as a double. */
static int jp_number(jp_t *j, double *out)
{
    const unsigned char *p = j->p, *e = j->e, *start = p;
    if (p < e && *p == '-') p++;
    if (p >= e) return 0;
    if (*p == '0') p++;
    else if (*p >= '1' && *p <= '9') while (p < e && *p >= '0' && *p <= '9') p++;
    else return 0;
    if (p < e && *p == '.') {
        p++;
        if (p >= e || *p < '0' || *p > '9') return 0;
        while (p < e && *p >= '0' && *p <= '9') p++;
    }
    if (p < e && (*p | 0x20) == 'e') {
        p++;
        if (p < e && (*p == '+' || *p == '-')) p++;
        if (p >= e || *p < '0' || *p > '9') return 0;
        while (p < e && *p >= '0' && *p <= '9') p++;
    }
    char tmp[64];
    size_t n = (size_t)(p - start);
    if (n >= sizeof tmp) return 0;
    memcpy(tmp, start, n);
    tmp[n] = 0;
    double v = strtod(tmp, NULL);
    if (v - v != 0) return 0; /* overflow to inf: not a usable number */
    *out = v;
    j->p = p;
    return 1;
}
static int jp_value(jp_t *j, int depth);
static int jp_container(jp_t *j, int depth, char close)
{
    j->p++;
    jp_ws(j);
    if (j->p < j->e && *j->p == close) { j->p++; return 1; }
    for (;;) {
        if (close == '}') {
            jp_ws(j);
            if (j->p >= j->e || *j->p != '"' || !jp_string(j, NULL, NULL)) return 0;
            jp_ws(j);
            if (j->p >= j->e || *j->p != ':') return 0;
            j->p++;
        }
        if (!jp_value(j, depth + 1)) return 0;
        jp_ws(j);
        if (j->p >= j->e) return 0;
        if (*j->p == ',') { j->p++; continue; }
        if (*j->p == close) { j->p++; return 1; }
        return 0;
    }
}
static int jp_value(jp_t *j, int depth)
{
    if (depth > 64) return 0;
    jp_ws(j);
    if (j->p >= j->e) return 0;
    switch (*j->p) {
    case '"': return jp_string(j, NULL, NULL);
    case '{': return jp_container(j, depth, '}');
    case '[': return jp_container(j, depth, ']');
    case 't': if (j->e - j->p >= 4 && !memcmp(j->p, "true", 4)) { j->p += 4; return 1; } return 0;
    case 'f': if (j->e - j->p >= 5 && !memcmp(j->p, "false", 5)) { j->p += 5; return 1; } return 0;
    case 'n': if (j->e - j->p >= 4 && !memcmp(j->p, "null", 4)) { j->p += 4; return 1; } return 0;
    default: { double d; return jp_number(j, &d); }
    }
}

/* One top-level member we care about. */
enum { JT_NONE, JT_STRING, JT_NUMBER, JT_OTHER };
typedef struct {
    const char *key;
    int type;
    const unsigned char *raw; /* string: position of the opening quote */
    size_t raw_len;
    double num;
} jfield_t;

/* Validates a whole document; if it is an object, fills the requested top-level fields (the last
 * occurrence of a duplicate key wins, as in JSON.parse). Returns -1 malformed, 0 not an object, 1 ok. */
static int json_object_fields(const unsigned char *s, size_t n, jfield_t *f, int nf)
{
    jp_t j = {s, s + n};
    for (int i = 0; i < nf; i++) f[i].type = JT_NONE;
    jp_ws(&j);
    if (j.p >= j.e) return -1;
    if (*j.p != '{') {
        if (!jp_value(&j, 0)) return -1;
        jp_ws(&j);
        return j.p == j.e ? 0 : -1;
    }
    j.p++;
    jp_ws(&j);
    if (j.p < j.e && *j.p == '}') { j.p++; goto end; }
    for (;;) {
        jp_ws(&j);
        if (j.p >= j.e || *j.p != '"') return -1;
        const unsigned char *k = j.p;
        if (!jp_string(&j, NULL, NULL)) return -1;
        size_t klen = (size_t)(j.p - k) - 2; /* raw key without quotes (escapes compared raw) */
        jp_ws(&j);
        if (j.p >= j.e || *j.p != ':') return -1;
        j.p++;
        jp_ws(&j);
        if (j.p >= j.e) return -1;
        jfield_t *hit = NULL;
        for (int i = 0; i < nf; i++)
            if (strlen(f[i].key) == klen && !memcmp(f[i].key, k + 1, klen)) hit = &f[i];
        const unsigned char *v = j.p;
        if (*v == '"') {
            if (!jp_string(&j, NULL, NULL)) return -1;
            if (hit) { hit->type = JT_STRING; hit->raw = v; hit->raw_len = (size_t)(j.p - v); }
        } else if (*v == '-' || (*v >= '0' && *v <= '9')) {
            double d;
            if (!jp_number(&j, &d)) return -1;
            if (hit) { hit->type = JT_NUMBER; hit->num = d; }
        } else {
            if (!jp_value(&j, 1)) return -1;
            if (hit) hit->type = JT_OTHER;
        }
        jp_ws(&j);
        if (j.p >= j.e) return -1;
        if (*j.p == ',') { j.p++; continue; }
        if (*j.p == '}') { j.p++; break; }
        return -1;
    }
end:
    jp_ws(&j);
    return j.p == j.e ? 1 : -1;
}
/* Decodes a validated string field into out (room for raw_len bytes). */
static size_t json_decode_string(const jfield_t *f, char *out)
{
    jp_t j = {f->raw, f->raw + f->raw_len};
    size_t n = 0;
    jp_string(&j, out, &n);
    return n;
}

/* ------------------------------------------------------------------------------------------------ */
/* JWT (HS256)                                                                                       */

static SHA256_CTX hmac_inner, hmac_outer; /* key pads hashed once at startup */

static void hmac_init(const char *key)
{
    unsigned char k[64] = {0}, pad[64];
    size_t kl = strlen(key);
    if (kl > 64) SHA256((const unsigned char *)key, kl, k);
    else memcpy(k, key, kl);
    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
    SHA256_Init(&hmac_inner);
    SHA256_Update(&hmac_inner, pad, 64);
    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5c;
    SHA256_Init(&hmac_outer);
    SHA256_Update(&hmac_outer, pad, 64);
}
static void hmac_sha256(const unsigned char *msg, size_t n, unsigned char out[32])
{
    SHA256_CTX c = hmac_inner;
    unsigned char inner[32];
    SHA256_Update(&c, msg, n);
    SHA256_Final(inner, &c);
    c = hmac_outer;
    SHA256_Update(&c, inner, 32);
    SHA256_Final(out, &c);
}

static signed char b64v[256];
static void b64_init(void)
{
    memset(b64v, -1, sizeof b64v);
    const char *a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for (int i = 0; i < 64; i++) b64v[(unsigned char)a[i]] = (signed char)i;
}
/* base64url without padding. Returns decoded length or -1. Rejects non-canonical trailing bits. */
static long b64url_decode(const unsigned char *s, size_t n, unsigned char *out)
{
    if (n % 4 == 1) return -1;
    size_t o = 0, i = 0;
    for (; i + 4 <= n; i += 4) {
        int a = b64v[s[i]], b = b64v[s[i + 1]], c = b64v[s[i + 2]], d = b64v[s[i + 3]];
        if ((a | b | c | d) < 0) return -1;
        uint32_t v = ((uint32_t)a << 18) | ((uint32_t)b << 12) | ((uint32_t)c << 6) | (uint32_t)d;
        out[o++] = (unsigned char)(v >> 16); out[o++] = (unsigned char)(v >> 8); out[o++] = (unsigned char)v;
    }
    size_t r = n - i;
    if (r == 2) {
        int a = b64v[s[i]], b = b64v[s[i + 1]];
        if ((a | b) < 0 || (b & 15)) return -1;
        out[o++] = (unsigned char)((a << 2) | (b >> 4));
    } else if (r == 3) {
        int a = b64v[s[i]], b = b64v[s[i + 1]], c = b64v[s[i + 2]];
        if ((a | b | c) < 0 || (c & 3)) return -1;
        out[o++] = (unsigned char)((a << 2) | (b >> 4));
        out[o++] = (unsigned char)((b << 4) | (c >> 2));
    }
    return (long)o;
}
static void b64url_encode32(const unsigned char in[32], char out[43])
{
    const char *a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    int o = 0, i = 0;
    for (; i + 3 <= 30; i += 3) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        out[o++] = a[v >> 18]; out[o++] = a[(v >> 12) & 63]; out[o++] = a[(v >> 6) & 63]; out[o++] = a[v & 63];
    }
    uint32_t v = ((uint32_t)in[30] << 16) | ((uint32_t)in[31] << 8);
    out[o++] = a[v >> 18]; out[o++] = a[(v >> 12) & 63]; out[o++] = a[(v >> 6) & 63];
}

#define HS256_HEADER "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" /* {"alg":"HS256","typ":"JWT"} */

typedef struct { int64_t uid; char name[512]; size_t name_len; } auth_t;

/* Returns 0 ok, else the error body to send with 401. */
static const char *authenticate(const char *hv, size_t hl, auth_t *a)
{
    if (!hv || hl < 7 || memcmp(hv, "Bearer ", 7)) return E_NO_TOKEN;
    const unsigned char *t = (const unsigned char *)hv + 7, *e = (const unsigned char *)hv + hl;
    const unsigned char *d1 = memchr(t, '.', (size_t)(e - t));
    if (!d1) return E_BAD_TOKEN;
    const unsigned char *d2 = memchr(d1 + 1, '.', (size_t)(e - d1 - 1));
    if (!d2 || memchr(d2 + 1, '.', (size_t)(e - d2 - 1))) return E_BAD_TOKEN;
    size_t hlen = (size_t)(d1 - t), plen = (size_t)(d2 - d1 - 1), slen = (size_t)(e - d2 - 1);
    unsigned char tmp[1024];
    if (hlen > sizeof tmp || plen > sizeof tmp || slen != 43) return E_BAD_TOKEN;
    if (!(hlen == sizeof HS256_HEADER - 1 && !memcmp(t, HS256_HEADER, hlen))) {
        long n = b64url_decode(t, hlen, tmp);
        if (n < 0) return E_BAD_TOKEN;
        jfield_t f[1] = {{.key = "alg"}};
        if (json_object_fields(tmp, (size_t)n, f, 1) != 1 || f[0].type != JT_STRING ||
            f[0].raw_len != 7 || memcmp(f[0].raw, "\"HS256\"", 7))
            return E_BAD_TOKEN;
    }
    unsigned char mac[32];
    char enc[43];
    hmac_sha256(t, (size_t)(d2 - t), mac);
    b64url_encode32(mac, enc);
    unsigned char diff = 0;
    for (int i = 0; i < 43; i++) diff |= (unsigned char)(enc[i] ^ d2[1 + i]);
    if (diff) return E_BAD_TOKEN;
    long n = b64url_decode(d1 + 1, plen, tmp);
    if (n < 0) return E_BAD_TOKEN;
    jfield_t f[4] = {{.key = "sub"}, {.key = "username"}, {.key = "exp"}, {.key = "nbf"}};
    if (json_object_fields(tmp, (size_t)n, f, 4) != 1) return E_BAD_TOKEN;
    struct timespec rt;
    clock_gettime(CLOCK_REALTIME, &rt);
    double now = (double)rt.tv_sec + rt.tv_nsec / 1e9; /* exp may be fractional */
    /* exp/nbf are optional (as in jsonwebtoken, PyJWT, golang-jwt), but must be numbers if present */
    if (f[2].type != JT_NONE && (f[2].type != JT_NUMBER || now >= f[2].num)) return E_BAD_TOKEN;
    if (f[3].type != JT_NONE && (f[3].type != JT_NUMBER || now < f[3].num)) return E_BAD_TOKEN;
    if (f[0].type != JT_STRING || f[1].type != JT_STRING) return E_BAD_PAYLOAD;
    /* sub: a positive decimal integer string with no escapes */
    const unsigned char *s = f[0].raw + 1;
    size_t sl = f[0].raw_len - 2;
    if (!sl || sl > 19) return E_BAD_PAYLOAD;
    uint64_t v = 0;
    for (size_t i = 0; i < sl; i++) {
        if (s[i] < '0' || s[i] > '9') return E_BAD_PAYLOAD;
        v = v * 10 + (uint64_t)(s[i] - '0');
    }
    if (v == 0 || v > (uint64_t)INT64_MAX) return E_BAD_PAYLOAD;
    if (f[1].raw_len > sizeof a->name) return E_BAD_PAYLOAD;
    a->uid = (int64_t)v;
    a->name_len = json_decode_string(&f[1], a->name);
    return NULL;
}

/* ------------------------------------------------------------------------------------------------ */
/* SQLite                                                                                            */

static sqlite3 *db;
static sqlite3_stmt *st_feed_ref, *st_post, *st_feed_ids, *st_feed_rows, *st_feed_likes, *st_create,
    *st_like, *st_exists, *st_ping, *st_begin, *st_commit, *st_rollback;
static int in_txn, txn_dirty, wal_frames;
/* Checkpoint once the WAL holds this many frames: a short WAL keeps walFindFrame (run for every page
 * read) cheap; at 4,000 frames it was 11% of CPU, at 1,000 about 2%. */
static int ck_frames = 1000;

static sqlite3_stmt *prep(const char *sql)
{
    sqlite3_stmt *s;
    if (sqlite3_prepare_v3(db, sql, -1, SQLITE_PREPARE_PERSISTENT, &s, NULL) != SQLITE_OK) {
        fprintf(stderr, "prepare: %s: %s\n", sqlite3_errmsg(db), sql);
        exit(1);
    }
    return s;
}
static int wal_hook(void *arg, sqlite3 *d, const char *name, int frames)
{
    (void)arg; (void)d; (void)name;
    wal_frames = frames;
    return SQLITE_OK;
}

#define POST_COLS "SELECT p.id, p.body, p.created_at, u.username, (SELECT count(*) FROM likes l WHERE l.post_id = p.id) FROM posts p JOIN users u ON u.id = p.user_id "

static void db_open(const char *path)
{
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX, NULL) != SQLITE_OK) {
        fprintf(stderr, "open %s: %s\n", path, sqlite3_errmsg(db));
        exit(1);
    }
    char *err = NULL;
    /* EXCLUSIVE before the first read: the WAL index lives in heap memory, no shm fcntl locks.
     * Checkpoints run explicitly after group commits (wal_autocheckpoint=0). */
    if (sqlite3_exec(db,
                     "PRAGMA locking_mode=EXCLUSIVE; PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;"
                     "PRAGMA foreign_keys=ON; PRAGMA mmap_size=1073741824; PRAGMA cache_size=-16384;"
                     "PRAGMA temp_store=MEMORY; PRAGMA wal_autocheckpoint=0; PRAGMA journal_size_limit=67108864;"
                     "SELECT count(*) FROM sqlite_schema;",
                     NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "pragmas: %s\n", err);
        exit(1);
    }
    sqlite3_wal_hook(db, wal_hook, NULL);
    st_feed_ref = prep(POST_COLS "ORDER BY p.created_at DESC, p.id DESC LIMIT 20");
    st_post = prep(POST_COLS "WHERE p.id = ?1");
    st_feed_ids = prep("SELECT id FROM posts ORDER BY created_at DESC, id DESC LIMIT 20");
    st_feed_rows = prep("SELECT p.id, p.body, p.created_at, u.username FROM posts p JOIN users u ON u.id = p.user_id "
                        "WHERE p.id BETWEEN ?1 AND ?2");
    st_feed_likes = prep("SELECT post_id FROM likes WHERE post_id BETWEEN ?1 AND ?2");
    st_create = prep("INSERT INTO posts (user_id, body) VALUES (?1, ?2) RETURNING id, created_at");
    st_like = prep("INSERT INTO likes (user_id, post_id) SELECT ?1, ?2 WHERE EXISTS (SELECT 1 FROM posts WHERE id = ?2) "
                   "ON CONFLICT (user_id, post_id) DO NOTHING");
    st_exists = prep("SELECT 1 FROM posts WHERE id = ?1");
    st_ping = prep("SELECT 1");
    st_begin = prep("BEGIN");
    st_commit = prep("COMMIT");
    st_rollback = prep("ROLLBACK");
}

/* The loop pass's transaction: opened by the first statement of a pass, committed at its end. */
static int txn(void)
{
    if (likely(in_txn)) return 1;
    int rc = sqlite3_step(st_begin);
    sqlite3_reset(st_begin);
    if (rc != SQLITE_DONE) return 0;
    in_txn = 1;
    txn_dirty = 0;
    return 1;
}
/* Returns 1 if committed (or nothing to commit), 0 if the pass's writes were lost. */
static int txn_end(void)
{
    if (!in_txn) return 1;
    in_txn = 0;
    int rc = sqlite3_step(st_commit);
    sqlite3_reset(st_commit);
    if (rc == SQLITE_DONE) {
        if (txn_dirty && wal_frames >= ck_frames) {
            sqlite3_wal_checkpoint_v2(db, NULL, SQLITE_CHECKPOINT_PASSIVE, NULL, NULL);
            wal_frames = 0;
        }
        return 1;
    }
    sqlite3_step(st_rollback);
    sqlite3_reset(st_rollback);
    return !txn_dirty;
}

static void post_json(buf_t *out, sqlite3_stmt *s, int64_t likes, int likes_col)
{
    const unsigned char *body = sqlite3_column_text(s, 1), *at = sqlite3_column_text(s, 2), *name = sqlite3_column_text(s, 3);
    int bl = sqlite3_column_bytes(s, 1), al = sqlite3_column_bytes(s, 2), nl = sqlite3_column_bytes(s, 3);
    buf_reserve(out, (uint32_t)(bl + al + nl) * 6 + 128);
    char *o = out->p + out->len;
#define RAW(lit) (memcpy(o, lit, sizeof(lit) - 1), o += sizeof(lit) - 1)
    RAW("{\"id\":");
    o = u64_raw(o, (uint64_t)sqlite3_column_int64(s, 0));
    RAW(",\"body\":");
    o = json_str_raw(o, body, bl);
    RAW(",\"created_at\":");
    o = json_str_raw(o, at, al);
    RAW(",\"author\":");
    o = json_str_raw(o, name, nl);
    RAW(",\"like_count\":");
    o = u64_raw(o, (uint64_t)(likes_col >= 0 ? sqlite3_column_int64(s, likes_col) : likes));
    *o++ = '}';
#undef RAW
    out->len = (uint32_t)(o - out->p);
}

#define FEED_SPAN 256
static int feed_ref(buf_t *out)
{
    int rc, first = 1;
    while ((rc = sqlite3_step(st_feed_ref)) == SQLITE_ROW) {
        if (!first) buf_put(out, ",", 1);
        first = 0;
        post_json(out, st_feed_ref, 0, 4);
    }
    sqlite3_reset(st_feed_ref);
    return rc == SQLITE_DONE;
}
/* The 20 newest posts, ORDER BY created_at DESC, id DESC. */
static int feed(buf_t *out)
{
    int64_t ids[20];
    int n = 0, rc;
    while (n < 20 && (rc = sqlite3_step(st_feed_ids)) == SQLITE_ROW) ids[n++] = sqlite3_column_int64(st_feed_ids, 0);
    sqlite3_reset(st_feed_ids);
    buf_lit(out, "{\"posts\":[");
    if (n == 0) { buf_lit(out, "]}"); return 1; }
    int64_t mn = ids[0], mx = ids[0];
    for (int i = 1; i < n; i++) { if (ids[i] < mn) mn = ids[i]; if (ids[i] > mx) mx = ids[i]; }
    if (mx - mn >= FEED_SPAN) {
        int ok = feed_ref(out);
        buf_lit(out, "]}");
        return ok;
    }
    /* slot[id - mn] -> position in ids, or -1 */
    signed char slot[FEED_SPAN];
    memset(slot, -1, (size_t)(mx - mn + 1));
    for (int i = 0; i < n; i++) slot[ids[i] - mn] = (signed char)i;
    int64_t likes[20] = {0};
    sqlite3_bind_int64(st_feed_likes, 1, mn);
    sqlite3_bind_int64(st_feed_likes, 2, mx);
    while ((rc = sqlite3_step(st_feed_likes)) == SQLITE_ROW) {
        int k = slot[sqlite3_column_int64(st_feed_likes, 0) - mn];
        if (k >= 0) likes[k]++;
    }
    sqlite3_reset(st_feed_likes);
    if (rc != SQLITE_DONE) return 0;
    /* render rows in range order into a scratch buffer, then emit them in feed order */
    static buf_t scratch;
    uint32_t off[20], len[20];
    int seen = 0;
    scratch.len = 0;
    sqlite3_bind_int64(st_feed_rows, 1, mn);
    sqlite3_bind_int64(st_feed_rows, 2, mx);
    while ((rc = sqlite3_step(st_feed_rows)) == SQLITE_ROW) {
        int k = slot[sqlite3_column_int64(st_feed_rows, 0) - mn];
        if (k < 0) continue;
        off[k] = scratch.len;
        post_json(&scratch, st_feed_rows, likes[k], -1);
        len[k] = scratch.len - off[k];
        seen++;
    }
    sqlite3_reset(st_feed_rows);
    if (rc != SQLITE_DONE) return 0;
    if (seen != n) { /* a post without its author row: the reference query decides */
        int ok = feed_ref(out);
        buf_lit(out, "]}");
        return ok;
    }
    for (int i = 0; i < n; i++) {
        if (i) buf_put(out, ",", 1);
        buf_put(out, scratch.p + off[i], len[i]);
    }
    buf_lit(out, "]}");
    return 1;
}

/* ------------------------------------------------------------------------------------------------ */
/* Request handling                                                                                  */

static time_t started_at;

/* Positive decimal id. Returns 0 if invalid, -1 if too large to exist (post not found). */
static int64_t parse_id(const char *s, size_t n)
{
    if (n == 0) return 0;
    uint64_t v = 0;
    int big = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return 0;
        if (!big) {
            v = v * 10 + (uint64_t)(s[i] - '0');
            if (v > (uint64_t)INT64_MAX) big = 1;
        }
    }
    if (big) return -1;
    return v ? (int64_t)v : 0;
}

/* JavaScript String.prototype.trim() whitespace (as UTF-8 code points). */
static int js_space(uint32_t c)
{
    return c == 0x09 || c == 0x0A || c == 0x0B || c == 0x0C || c == 0x0D || c == 0x20 || c == 0xA0 ||
           c == 0x1680 || (c >= 0x2000 && c <= 0x200A) || c == 0x2028 || c == 0x2029 || c == 0x202F ||
           c == 0x205F || c == 0x3000 || c == 0xFEFF;
}

static void handle_create(buf_t *out, int close, const char *authv, size_t authl, const char *body, size_t bl)
{
    auth_t a;
    const char *err = authenticate(authv, authl, &a);
    if (err) { respond_raw(out, 401, close, err, (uint32_t)strlen(err)); return; }
    jfield_t f[1] = {{.key = "body"}};
    int r = json_object_fields((const unsigned char *)body, bl, f, 1);
    if (r < 0) { respond_lit(out, 400, close, E_BAD_JSON); return; }
    if (r == 0 || f[0].type != JT_STRING) { respond_lit(out, 400, close, E_NO_BODY); return; }
    char *text = malloc(f[0].raw_len + 1);
    if (!text) { respond_lit(out, 500, close, E_INTERNAL); return; }
    size_t n = json_decode_string(&f[0], text);
    /* trim JS whitespace from both ends; count code points */
    size_t s = 0, e = n;
    for (;;) {
        uint32_t cp;
        if (s >= e) break;
        int l = utf8_len((unsigned char *)text + s, e - s, &cp);
        if (l && js_space(cp)) s += (size_t)l; else break;
    }
    while (e > s) {
        size_t b = e - 1;
        while (b > s && ((unsigned char)text[b] & 0xC0) == 0x80) b--;
        uint32_t cp;
        int l = utf8_len((unsigned char *)text + b, e - b, &cp);
        if (l && (size_t)l == e - b && js_space(cp)) e = b; else break;
    }
    size_t chars = 0;
    for (size_t i = s; i < e; i++) chars += (((unsigned char)text[i] & 0xC0) != 0x80);
    if (chars == 0) { free(text); respond_lit(out, 400, close, E_NO_BODY); return; }
    if (chars > 500) { free(text); respond_lit(out, 400, close, E_LONG_BODY); return; }
    if (!txn()) { free(text); respond_lit(out, 500, close, E_INTERNAL); return; }
    sqlite3_bind_int64(st_create, 1, a.uid);
    sqlite3_bind_text(st_create, 2, text + s, (int)(e - s), SQLITE_STATIC);
    int rc = sqlite3_step(st_create);
    if (rc != SQLITE_ROW) {
        sqlite3_reset(st_create);
        free(text);
        respond_lit(out, 500, close, E_INTERNAL);
        return;
    }
    txn_dirty = 1;
    uint32_t at = head_begin(out, 201, close);
    buf_lit(out, "{\"post\":{\"id\":");
    buf_u64(out, (uint64_t)sqlite3_column_int64(st_create, 0));
    buf_lit(out, ",\"body\":");
    buf_json_str(out, (unsigned char *)text + s, (int)(e - s));
    buf_lit(out, ",\"created_at\":");
    buf_json_str(out, sqlite3_column_text(st_create, 1), sqlite3_column_bytes(st_create, 1));
    buf_lit(out, ",\"author\":");
    buf_json_str(out, (unsigned char *)a.name, (int)a.name_len);
    buf_lit(out, ",\"like_count\":0}}");
    head_end(out, at);
    while (sqlite3_step(st_create) == SQLITE_ROW) {}
    sqlite3_reset(st_create);
    free(text);
}

static void handle_like(buf_t *out, int close, const char *authv, size_t authl, const char *id, size_t idl)
{
    auth_t a;
    const char *err = authenticate(authv, authl, &a);
    if (err) { respond_raw(out, 401, close, err, (uint32_t)strlen(err)); return; }
    int64_t pid = parse_id(id, idl);
    if (pid == 0) { respond_lit(out, 400, close, E_BAD_ID); return; }
    if (pid < 0) { respond_lit(out, 404, close, E_NO_POST); return; }
    if (!txn()) { respond_lit(out, 500, close, E_INTERNAL); return; }
    sqlite3_bind_int64(st_like, 1, a.uid);
    sqlite3_bind_int64(st_like, 2, pid);
    int rc = sqlite3_step(st_like);
    sqlite3_reset(st_like);
    if (rc != SQLITE_DONE) { respond_lit(out, 500, close, E_INTERNAL); return; }
    int added = sqlite3_changes(db) == 1;
    if (!added) {
        sqlite3_bind_int64(st_exists, 1, pid);
        rc = sqlite3_step(st_exists);
        sqlite3_reset(st_exists);
        if (rc == SQLITE_DONE) { respond_lit(out, 404, close, E_NO_POST); return; }
        if (rc != SQLITE_ROW) { respond_lit(out, 500, close, E_INTERNAL); return; }
    } else txn_dirty = 1;
    uint32_t at = head_begin(out, added ? 201 : 200, close);
    buf_lit(out, "{\"liked\":true,\"already_liked\":");
    if (added) buf_lit(out, "false"); else buf_lit(out, "true");
    buf_lit(out, ",\"post_id\":");
    buf_u64(out, (uint64_t)pid);
    buf_put(out, "}", 1);
    head_end(out, at);
}

static void handle_get_post(buf_t *out, int close, const char *id, size_t idl)
{
    int64_t pid = parse_id(id, idl);
    if (pid == 0) { respond_lit(out, 400, close, E_BAD_ID); return; }
    if (pid < 0) { respond_lit(out, 404, close, E_NO_POST); return; }
    if (!txn()) { respond_lit(out, 500, close, E_INTERNAL); return; }
    sqlite3_bind_int64(st_post, 1, pid);
    int rc = sqlite3_step(st_post);
    if (rc == SQLITE_ROW) {
        uint32_t at = head_begin(out, 200, close);
        buf_lit(out, "{\"post\":");
        post_json(out, st_post, 0, 4);
        buf_put(out, "}", 1);
        head_end(out, at);
    } else if (rc == SQLITE_DONE) respond_lit(out, 404, close, E_NO_POST);
    else respond_lit(out, 500, close, E_INTERNAL);
    sqlite3_reset(st_post);
}

static void handle_feed(buf_t *out, int close)
{
    if (!txn()) { respond_lit(out, 500, close, E_INTERNAL); return; }
    uint32_t mark = out->len;
    uint32_t at = head_begin(out, 200, close);
    if (!feed(out)) {
        out->len = mark;
        respond_lit(out, 500, close, E_INTERNAL);
        return;
    }
    head_end(out, at);
}

static void handle_health(buf_t *out, int close)
{
    int ok = txn();
    int rc = ok ? sqlite3_step(st_ping) : SQLITE_ERROR;
    sqlite3_reset(st_ping);
    if (rc == SQLITE_ROW) {
        uint32_t at = head_begin(out, 200, close);
        buf_lit(out, "{\"status\":\"ok\",\"db\":\"ok\",\"uptime_s\":");
        buf_u64(out, (uint64_t)(time(NULL) - started_at));
        buf_put(out, "}", 1);
        head_end(out, at);
    } else {
        const char *msg = sqlite3_errmsg(db);
        uint32_t at = head_begin(out, 503, close);
        buf_lit(out, "{\"status\":\"degraded\",\"db\":\"unreachable\",\"error\":");
        buf_json_str(out, (const unsigned char *)msg, (int)strlen(msg));
        buf_put(out, "}", 1);
        head_end(out, at);
    }
}

static void route(buf_t *out, int close, const char *m, size_t ml, const char *path, size_t pl,
                  const char *authv, size_t authl, const char *body, size_t bl)
{
    const char *q = memchr(path, '?', pl);
    if (q) pl = (size_t)(q - path);
    if (ml == 3 && !memcmp(m, "GET", 3)) {
        if (pl == 5 && !memcmp(path, "/feed", 5)) { handle_feed(out, close); return; }
        if (pl > 7 && !memcmp(path, "/posts/", 7) && !memchr(path + 7, '/', pl - 7))
            { handle_get_post(out, close, path + 7, pl - 7); return; }
        if (pl == 7 && !memcmp(path, "/health", 7)) { handle_health(out, close); return; }
    } else if (ml == 4 && !memcmp(m, "POST", 4)) {
        if (pl == 6 && !memcmp(path, "/posts", 6)) { handle_create(out, close, authv, authl, body, bl); return; }
        if (pl > 12 && !memcmp(path, "/posts/", 7) && !memcmp(path + pl - 5, "/like", 5) &&
            !memchr(path + 7, '/', pl - 12))
            { handle_like(out, close, authv, authl, path + 7, pl - 12); return; }
    }
    respond_lit(out, 404, close, E_NOT_FOUND);
}

/* ------------------------------------------------------------------------------------------------ */
/* Connections and rings                                                                             */

enum { OP_ACCEPT = 1, OP_RECV, OP_SEND, OP_CLOSE, OP_CANCEL };

typedef struct {
    uint16_t gen;
    uint8_t open, sending, close_after, closing, recv_armed, dirty, continued, oneshot, linked_close;
    uint32_t last_active;
    uint32_t batch_mark, batch_reqs; /* output and request count produced in this pass */
    buf_t in;                        /* unparsed input (only while a request is partial)    */
    buf_t out;                       /* output not yet handed to the kernel                  */
    buf_t inflight;                  /* output owned by an in-flight send                     */
    uint32_t inflight_off;
} conn_t;

typedef struct {
    struct io_uring ring;
    struct io_uring_buf_ring *br;
    unsigned char *bufs;
    conn_t *conns;
    unsigned nslots, used;
    int accepting;
} ring_t;

static ring_t rings[MAX_RINGS];
static int nrings, accept_ring = -1, listen_fd;
static unsigned slots_per_ring, total_open;
static unsigned *dirty_list; /* (ring << 20 | slot) of conns with output this pass */
static unsigned ndirty, dirty_cap;

static inline uint64_t ud(int op, int r, unsigned slot, uint16_t gen)
{
    return ((uint64_t)op << 56) | ((uint64_t)r << 48) | ((uint64_t)gen << 32) | slot;
}

static struct io_uring_sqe *sqe_get(ring_t *r)
{
    struct io_uring_sqe *s = io_uring_get_sqe(&r->ring);
    if (unlikely(!s)) {
        io_uring_submit(&r->ring);
        s = io_uring_get_sqe(&r->ring);
        if (!s) die("io_uring_get_sqe");
    }
    return s;
}

static void arm_accept(int ri)
{
    ring_t *r = &rings[ri];
    struct io_uring_sqe *s = sqe_get(r);
    io_uring_prep_multishot_accept_direct(s, listen_fd, NULL, NULL, 0);
    io_uring_sqe_set_data64(s, ud(OP_ACCEPT, ri, 0, 0));
    r->accepting = 1;
    accept_ring = ri;
}

static void arm_recv(int ri, unsigned slot)
{
    ring_t *r = &rings[ri];
    conn_t *c = &r->conns[slot];
    struct io_uring_sqe *s = sqe_get(r);
    if (c->oneshot) io_uring_prep_recv(s, (int)slot, NULL, BUF_SIZE, 0);
    else io_uring_prep_recv_multishot(s, (int)slot, NULL, 0, 0);
    s->flags |= IOSQE_FIXED_FILE | IOSQE_BUFFER_SELECT;
    s->buf_group = 0;
    io_uring_sqe_set_data64(s, ud(OP_RECV, ri, slot, c->gen));
    c->recv_armed = 1;
}

static void conn_close(int ri, unsigned slot)
{
    ring_t *r = &rings[ri];
    conn_t *c = &r->conns[slot];
    if (!c->open) return;
    if (c->sending) { /* the kernel still owns c->inflight: close once the send completes */
        c->close_after = 1;
        c->closing = 1;
        return;
    }
    c->open = 0;
    c->closing = 0;
    c->gen++;
    buf_free(&c->in);
    buf_free(&c->out);
    buf_free(&c->inflight);
    struct io_uring_sqe *s;
    if (c->recv_armed) {
        /* Not IORING_OP_ASYNC_CANCEL: cancel-by-fd scans every in-flight request, which is quadratic
         * with tens of thousands of armed recvs. shutdown() ends the armed recv with EOF by itself. */
        s = sqe_get(r);
        io_uring_prep_shutdown(s, (int)slot, SHUT_RDWR);
        s->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
        io_uring_sqe_set_data64(s, ud(OP_CANCEL, ri, slot, 0));
        c->recv_armed = 0;
    }
    s = sqe_get(r);
    io_uring_prep_close_direct(s, slot);
    io_uring_sqe_set_data64(s, ud(OP_CLOSE, ri, slot, 0));
    total_open--;
    r->used--;
}

static void mark_dirty(int ri, unsigned slot, conn_t *c)
{
    if (c->dirty) return;
    c->dirty = 1;
    c->batch_mark = c->out.len;
    c->batch_reqs = 0;
    if (ndirty == dirty_cap) {
        dirty_cap = dirty_cap ? dirty_cap * 2 : 4096;
        dirty_list = realloc(dirty_list, dirty_cap * sizeof *dirty_list);
        if (!dirty_list) die("realloc");
    }
    dirty_list[ndirty++] = ((unsigned)ri << 20) | slot;
}

static void start_send(int ri, unsigned slot)
{
    ring_t *r = &rings[ri];
    conn_t *c = &r->conns[slot];
    if (c->sending || !c->out.len) return;
    buf_free(&c->inflight);
    c->inflight = c->out; /* the kernel owns it until the send completes */
    c->out = (buf_t){0};
    c->inflight_off = 0;
    c->sending = 1;
    struct io_uring_sqe *s = sqe_get(r);
    if (c->close_after) {
        /* send + close in one submission: MSG_WAITALL retries short sends, the links close after
         * (through shutdown when a recv is still armed, so it ends without a cancel scan) */
        io_uring_prep_send(s, (int)slot, c->inflight.p, c->inflight.len, MSG_NOSIGNAL | MSG_WAITALL);
        s->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
        io_uring_sqe_set_data64(s, ud(OP_SEND, ri, slot, c->gen));
        if (c->recv_armed) {
            struct io_uring_sqe *sh = sqe_get(r);
            io_uring_prep_shutdown(sh, (int)slot, SHUT_RDWR);
            sh->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
            io_uring_sqe_set_data64(sh, ud(OP_CANCEL, ri, slot, 0));
            c->recv_armed = 0;
        }
        struct io_uring_sqe *cl = sqe_get(r);
        io_uring_prep_close_direct(cl, slot);
        io_uring_sqe_set_data64(cl, ud(OP_CLOSE, ri, slot, 0));
        c->linked_close = 1;
        return;
    }
    io_uring_prep_send(s, (int)slot, c->inflight.p, c->inflight.len, MSG_NOSIGNAL);
    s->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data64(s, ud(OP_SEND, ri, slot, c->gen));
}

/* Parses and answers every complete request in data. */
static void serve_bytes(int ri, unsigned slot, conn_t *c, const char *data, size_t n)
{
    const char *p = data, *end = data + n;
    while (p < end && !c->close_after) {
        const char *he = memmem(p, (size_t)(end - p), "\r\n\r\n", 4);
        if (!he) {
            if ((size_t)(end - p) > MAX_HEAD) {
                mark_dirty(ri, slot, c);
                respond_lit(&c->out, 431, 1, E_HEAD_TOO_LARGE);
                c->batch_reqs++;
                c->close_after = 1;
                p = end;
            }
            break;
        }
        const char *le = memchr(p, '\r', (size_t)(he + 2 - p));
        const char *sp1 = memchr(p, ' ', (size_t)(le - p));
        const char *sp2 = sp1 ? memrchr(sp1 + 1, ' ', (size_t)(le - sp1 - 1)) : NULL;
        if (!sp1 || !sp2 || sp1 == p) {
            mark_dirty(ri, slot, c);
            respond_lit(&c->out, 400, 1, E_BAD_REQUEST);
            c->batch_reqs++;
            c->close_after = 1;
            p = end;
            break;
        }
        int http11 = (le - sp2 - 1) == 8 && !memcmp(sp2 + 1, "HTTP/1.1", 8);
        int keep = http11, chunked = 0, expect = 0, has_cl = 0, conn_close_tok = 0, conn_keep_tok = 0;
        long long cl = 0;
        const char *authv = NULL;
        size_t authl = 0;
        /* headers: lines between le+2 and he+2 */
        for (const char *h = le + 2; h < he + 2;) {
            const char *eol = memchr(h, '\r', (size_t)(he + 2 - h));
            if (!eol) break;
            const char *colon = memchr(h, ':', (size_t)(eol - h));
            if (colon) {
                size_t nl = (size_t)(colon - h);
                const char *v = colon + 1, *ve = eol;
                while (v < ve && (*v == ' ' || *v == '\t')) v++;
                while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t')) ve--;
                switch (h[0] | 0x20) {
                case 'a':
                    if (nl == 13 && !strncasecmp(h, "authorization", 13)) { authv = v; authl = (size_t)(ve - v); }
                    break;
                case 'c':
                    if (nl == 14 && !strncasecmp(h, "content-length", 14)) {
                        has_cl = 1;
                        cl = 0;
                        if (v == ve) cl = -1;
                        for (const char *d = v; d < ve; d++) {
                            if (*d < '0' || *d > '9' || cl > MAX_BODY) { cl = -1; break; }
                            cl = cl * 10 + (*d - '0');
                        }
                    } else if (nl == 10 && !strncasecmp(h, "connection", 10)) {
                        /* a comma-separated token list: "close", "keep-alive", "TE, close", ... */
                        for (const char *t = v; t < ve;) {
                            const char *te = memchr(t, ',', (size_t)(ve - t));
                            if (!te) te = ve;
                            const char *a = t, *b = te;
                            while (a < b && (*a == ' ' || *a == '\t')) a++;
                            while (b > a && (b[-1] == ' ' || b[-1] == '\t')) b--;
                            if (b - a == 5 && !strncasecmp(a, "close", 5)) conn_close_tok = 1;
                            else if (b - a == 10 && !strncasecmp(a, "keep-alive", 10)) conn_keep_tok = 1;
                            t = te + 1;
                        }
                    }
                    break;
                case 't':
                    if (nl == 17 && !strncasecmp(h, "transfer-encoding", 17))
                        /* only chunked is supported, and it must be the last coding */
                        chunked = (ve - v) >= 7 && !strncasecmp(ve - 7, "chunked", 7) ? 1 : -1;
                    break;
                case 'e':
                    if (nl == 6 && !strncasecmp(h, "expect", 6) && (size_t)(ve - v) == 12 &&
                        !strncasecmp(v, "100-continue", 12))
                        expect = 1;
                    break;
                }
            }
            h = eol + 2;
        }
        if (conn_close_tok) keep = 0;
        else if (conn_keep_tok) keep = 1;
        if (chunked < 0 || (chunked && has_cl)) { /* unknown coding, or both framings (RFC 9112 6.3) */
            mark_dirty(ri, slot, c);
            respond_lit(&c->out, 400, 1, E_BAD_REQUEST);
            c->batch_reqs++;
            c->close_after = 1;
            p = end;
            break;
        }
        const char *body = he + 4;
        size_t bl = 0;
        const char *next;
        static buf_t chunkbuf;
        if (chunked) {
            chunkbuf.len = 0;
            const char *q = body;
            int done = 0, bad = 0;
            for (;;) {
                const char *ce = memmem(q, (size_t)(end - q), "\r\n", 2);
                if (!ce) break;
                unsigned long long sz = 0;
                const char *d = q;
                for (; d < ce && *d != ';'; d++) {
                    int x = (*d >= '0' && *d <= '9') ? *d - '0' : ((*d | 0x20) >= 'a' && (*d | 0x20) <= 'f') ? (*d | 0x20) - 'a' + 10 : -1;
                    if (x < 0 || sz > MAX_BODY) { bad = 1; break; }
                    sz = sz * 16 + (unsigned)x;
                }
                if (bad || d == q) { bad = 1; break; }
                if (sz == 0) {
                    const char *te = memmem(ce, (size_t)(end - ce), "\r\n\r\n", 4);
                    if (te) { next = te + 4; done = 1; }
                    break;
                }
                if (chunkbuf.len + sz > MAX_BODY) { bad = 1; break; }
                if ((size_t)(end - (ce + 2)) < sz + 2) break;
                buf_put(&chunkbuf, ce + 2, (uint32_t)sz);
                q = ce + 2 + sz + 2;
            }
            if (bad) {
                mark_dirty(ri, slot, c);
                respond_lit(&c->out, 400, 1, E_BAD_REQUEST);
                c->batch_reqs++;
                c->close_after = 1;
                p = end;
                break;
            }
            if (!done) break; /* incomplete */
            body = chunkbuf.p;
            bl = chunkbuf.len;
        } else {
            if (cl < 0) {
                mark_dirty(ri, slot, c);
                respond_lit(&c->out, cl == -1 ? 400 : 413, 1, E_BAD_REQUEST);
                c->batch_reqs++;
                c->close_after = 1;
                p = end;
                break;
            }
            if ((size_t)(end - body) < (size_t)cl) {
                if (expect && !c->continued && c->out.len == 0 && !c->sending) {
                    c->continued = 1;
                    mark_dirty(ri, slot, c);
                    buf_lit(&c->out, "HTTP/1.1 100 Continue\r\n\r\n");
                }
                break; /* wait for the body */
            }
            bl = (size_t)cl;
            next = body + cl;
        }
        c->continued = 0;
        if (keep && c->oneshot) keep = 0; /* accepted above the keep-alive budget: one request */
        mark_dirty(ri, slot, c);
        route(&c->out, !keep, p, (size_t)(sp1 - p), sp1 + 1, (size_t)(sp2 - sp1 - 1), authv, authl, body, bl);
        c->batch_reqs++;
        p = next;
        if (!keep) { c->close_after = 1; p = end; }
    }
    /* keep the unparsed tail */
    size_t rest = (size_t)(end - p);
    if (rest == 0) { buf_free(&c->in); return; }
    if (data == c->in.p) {
        memmove(c->in.p, p, rest);
        c->in.len = (uint32_t)rest;
    } else {
        c->in.len = 0;
        buf_put(&c->in, p, (uint32_t)rest);
    }
}

/* Drops a connection now, even mid-send: shutdown() fails a send the client is not reading. */
static void conn_abort(int ri, unsigned slot)
{
    ring_t *r = &rings[ri];
    conn_t *c = &r->conns[slot];
    if (!c->sending) { c->out.len = 0; conn_close(ri, slot); return; }
    c->out.len = 0;
    c->close_after = c->closing = 1;
    struct io_uring_sqe *s = sqe_get(r);
    io_uring_prep_shutdown(s, (int)slot, SHUT_RDWR);
    s->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data64(s, ud(OP_CANCEL, ri, slot, 0));
}

static void on_recv(int ri, struct io_uring_cqe *cqe, unsigned slot, uint16_t gen)
{
    ring_t *r = &rings[ri];
    conn_t *c = &r->conns[slot];
    int res = cqe->res;
    int more = cqe->flags & IORING_CQE_F_MORE;
    if (cqe->flags & IORING_CQE_F_BUFFER) {
        unsigned bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
        unsigned char *b = r->bufs + (size_t)bid * BUF_SIZE;
        if (res > 0 && c->open && c->gen == gen && !c->close_after) {
            c->last_active = now_sec;
            if ((size_t)c->out.len + c->inflight.len > MAX_PENDING_OUT) conn_abort(ri, slot);
            else if (c->in.len) {
                buf_put(&c->in, b, (uint32_t)res);
                serve_bytes(ri, slot, c, c->in.p, c->in.len);
            } else serve_bytes(ri, slot, c, (const char *)b, (size_t)res);
        }
        io_uring_buf_ring_add(r->br, b, BUF_SIZE, (unsigned short)bid, io_uring_buf_ring_mask(BUF_COUNT), 0);
        io_uring_buf_ring_advance(r->br, 1);
    }
    if (!c->open || c->gen != gen) return;
    if (res == 0 || (res < 0 && res != -ENOBUFS)) {
        if (!c->sending && !c->out.len) conn_close(ri, slot);
        else c->close_after = 1; /* finish sending, then close */
        c->recv_armed = 0;
        return;
    }
    if (!more) {
        c->recv_armed = 0;
        if (!c->close_after) arm_recv(ri, slot); /* also re-arms a oneshot conn whose request was partial */
    }
}

static void on_send(int ri, struct io_uring_cqe *cqe, unsigned slot, uint16_t gen)
{
    ring_t *r = &rings[ri];
    conn_t *c = &r->conns[slot];
    if (!c->open || c->gen != gen) return;
    c->sending = 0;
    if (c->linked_close) { /* the kernel closes the slot right after this send */
        c->linked_close = 0;
        if (cqe->res < (int)c->inflight.len) { /* failed or short: the linked shutdown/close were cancelled */
            struct io_uring_sqe *s = sqe_get(r);
            io_uring_prep_shutdown(s, (int)slot, SHUT_RDWR);
            s->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
            io_uring_sqe_set_data64(s, ud(OP_CANCEL, ri, slot, 0));
            s = sqe_get(r);
            io_uring_prep_close_direct(s, slot);
            io_uring_sqe_set_data64(s, ud(OP_CLOSE, ri, slot, 0));
        }
        c->open = 0;
        c->closing = 0;
        c->gen++;
        buf_free(&c->in);
        buf_free(&c->out);
        buf_free(&c->inflight);
        total_open--;
        r->used--;
        return;
    }
    if (cqe->res < 0) { c->out.len = 0; conn_close(ri, slot); return; }
    c->inflight_off += (uint32_t)cqe->res;
    if (c->inflight_off < c->inflight.len && !c->closing) { /* partial: send the rest */
        c->sending = 1;
        struct io_uring_sqe *s = sqe_get(r);
        io_uring_prep_send(s, (int)slot, c->inflight.p + c->inflight_off, c->inflight.len - c->inflight_off, MSG_NOSIGNAL);
        s->flags |= IOSQE_FIXED_FILE;
        io_uring_sqe_set_data64(s, ud(OP_SEND, ri, slot, c->gen));
        return;
    }
    buf_free(&c->inflight); /* idle connections hold no buffers */
    if (c->closing) { conn_close(ri, slot); return; }
    if (c->out.len && !c->dirty) start_send(ri, slot);
    else if (c->close_after && !c->out.len && !c->dirty) conn_close(ri, slot);
}

static void on_accept(int ri, struct io_uring_cqe *cqe)
{
    ring_t *r = &rings[ri];
    int res = cqe->res;
    if (res >= 0) {
        unsigned slot = (unsigned)res;
        conn_t *c = &r->conns[slot];
        c->open = 1;
        c->sending = c->close_after = c->closing = c->dirty = c->continued = c->linked_close = 0;
        c->oneshot = total_open >= KEEPALIVE_BUDGET; /* will be answered with Connection: close */
        c->in.len = c->out.len = 0;
        c->last_active = now_sec;
        r->used++;
        total_open++;
        arm_recv(ri, slot);
    }
    if (!(cqe->flags & IORING_CQE_F_MORE)) {
        r->accepting = 0;
        if (res == -ENFILE || r->used >= r->nslots) {
            /* table full: move on to the next ring with room (or back to this one later) */
            for (int k = 1; k <= nrings; k++) {
                int nr = (ri + k) % nrings;
                if (rings[nr].used + 64 < rings[nr].nslots) { arm_accept(nr); return; }
            }
            accept_ring = -1; /* every ring full: retried by the sweep */
        } else arm_accept(ri);
    }
}

/* End of a loop pass: commit, then hand every reply of the pass to the kernel. */
static void flush_pass(void)
{
    if (!txn_end()) {
        /* the pass's writes were lost: every reply of the pass becomes a 500 */
        for (unsigned i = 0; i < ndirty; i++) {
            ring_t *r = &rings[dirty_list[i] >> 20];
            conn_t *c = &r->conns[dirty_list[i] & 0xFFFFF];
            c->out.len = c->batch_mark;
            for (unsigned k = 0; k < c->batch_reqs; k++) respond_lit(&c->out, 500, 1, E_INTERNAL);
            c->close_after = 1;
        }
    }
    for (unsigned i = 0; i < ndirty; i++) {
        int ri = (int)(dirty_list[i] >> 20);
        unsigned slot = dirty_list[i] & 0xFFFFF;
        conn_t *c = &rings[ri].conns[slot];
        c->dirty = 0;
        if (!c->open) continue;
        start_send(ri, slot);
        if (!c->sending && c->close_after) conn_close(ri, slot);
    }
    ndirty = 0;
}

static void process(int ri, struct io_uring_cqe *cqe)
{
    uint64_t u = cqe->user_data;
    int op = (int)(u >> 56);
    unsigned slot = (unsigned)(u & 0xFFFFFFFF);
    uint16_t gen = (uint16_t)(u >> 32);
    switch (op) {
    case OP_RECV: on_recv(ri, cqe, slot, gen); break;
    case OP_SEND: on_send(ri, cqe, slot, gen); break;
    case OP_ACCEPT: on_accept(ri, cqe); break;
    default: break; /* close / cancel completions */
    }
}

static void sweep(void)
{
    static uint32_t last;
    if (now_sec - last < 15) return;
    last = now_sec;
    for (int ri = 0; ri < nrings; ri++)
        for (unsigned s = 0; s < rings[ri].nslots; s++) {
            conn_t *c = &rings[ri].conns[s];
            if (c->open && !c->sending && !c->dirty && now_sec - c->last_active > IDLE_SECONDS) conn_close(ri, s);
        }
    if (accept_ring < 0)
        for (int ri = 0; ri < nrings; ri++)
            if (rings[ri].used + 64 < rings[ri].nslots) { arm_accept(ri); break; }
}

static int init_ring(int ri)
{
    ring_t *r = &rings[ri];
    struct io_uring_params p;
    memset(&p, 0, sizeof p);
    p.flags = IORING_SETUP_CQSIZE | IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN;
    p.cq_entries = CQ_ENTRIES;
    if (io_uring_queue_init_params(SQ_ENTRIES, &r->ring, &p) < 0) {
        memset(&p, 0, sizeof p);
        p.flags = IORING_SETUP_CQSIZE | IORING_SETUP_COOP_TASKRUN;
        p.cq_entries = CQ_ENTRIES;
        if (io_uring_queue_init_params(SQ_ENTRIES, &r->ring, &p) < 0) return 0;
    }
    if (io_uring_register_files_sparse(&r->ring, slots_per_ring) < 0) { io_uring_queue_exit(&r->ring); return 0; }
    int err;
    r->br = io_uring_setup_buf_ring(&r->ring, BUF_COUNT, 0, 0, &err);
    if (!r->br) { io_uring_queue_exit(&r->ring); return 0; }
    r->bufs = aligned_alloc(4096, (size_t)BUF_COUNT * BUF_SIZE);
    r->conns = calloc(slots_per_ring, sizeof(conn_t));
    if (!r->bufs || !r->conns) die("alloc");
    for (unsigned i = 0; i < BUF_COUNT; i++)
        io_uring_buf_ring_add(r->br, r->bufs + (size_t)i * BUF_SIZE, BUF_SIZE, (unsigned short)i,
                              io_uring_buf_ring_mask(BUF_COUNT), (int)i);
    io_uring_buf_ring_advance(r->br, BUF_COUNT);
    r->nslots = slots_per_ring;
    return 1;
}

static int make_listener(const char *host, const char *port)
{
    struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM, .ai_flags = AI_PASSIVE}, *ai;
    int rc = getaddrinfo(host, port, &hints, &ai);
    if (rc) { fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc)); exit(1); }
    int fd = socket(ai->ai_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) die("socket");
    int one = 1, defer = 2;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    /* accept() completes only once the request has arrived: a new connection is served at once */
    setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &defer, sizeof defer);
    if (bind(fd, ai->ai_addr, ai->ai_addrlen)) die("bind");
    if (listen(fd, 4096)) die("listen");
    freeaddrinfo(ai);
    return fd;
}

int main(void)
{
    const char *path = getenv("SQLITE_PATH"), *secret = getenv("JWT_SECRET");
    const char *host = getenv("HOST"), *port = getenv("PORT");
    if (!path || !secret) { fprintf(stderr, "SQLITE_PATH and JWT_SECRET are required\n"); return 1; }
    if (!host) host = "127.0.0.1";
    if (!port) port = "3000";
    signal(SIGPIPE, SIG_IGN);
    started_at = time(NULL);
    refresh_clock();
    b64_init();
    hmac_init(secret);
    db_open(path);

    struct rlimit rl;
    getrlimit(RLIMIT_NOFILE, &rl);
    rl.rlim_cur = rl.rlim_max;
    setrlimit(RLIMIT_NOFILE, &rl);
    getrlimit(RLIMIT_NOFILE, &rl);
    slots_per_ring = rl.rlim_cur > 65535 ? 65535 : (unsigned)rl.rlim_cur;
    if (slots_per_ring > 256) slots_per_ring -= 64; /* leave descriptors for SQLite and the rings */

    listen_fd = make_listener(host, port);
    while (nrings < MAX_RINGS && init_ring(nrings)) nrings++;
    if (!nrings) { fprintf(stderr, "io_uring setup failed (kernel 6.1+ with io_uring enabled is required)\n"); return 1; }
    /* keep-alive connections plus one-request connections in flight must fit the fixed table */
    if (KEEPALIVE_BUDGET + 4096 > slots_per_ring) KEEPALIVE_BUDGET = slots_per_ring > 8192 ? slots_per_ring - 4096 : slots_per_ring / 2;
    arm_accept(0);
    fprintf(stderr, "listening on %s:%s, %u fixed slots, keep-alive budget %u\n", host, port, slots_per_ring, KEEPALIVE_BUDGET);

    struct __kernel_timespec busy_ts = {.tv_sec = 0, .tv_nsec = BATCH_USEC * 1000L};
    struct __kernel_timespec idle_ts = {.tv_sec = 1, .tv_nsec = 0};
    ring_t *r0 = &rings[0];
    unsigned last = 0;
    for (;;) {
        struct io_uring_cqe *cqe;
        /* busy: wait for a batch (fewer syscalls, bigger group commits); quiet: wake for each event */
        io_uring_submit_and_wait_timeout(&r0->ring, &cqe, last >= 8 ? BATCH_WAIT : 1, last >= 8 ? &busy_ts : &idle_ts, NULL);
        refresh_clock();
        unsigned head, count = 0;
        io_uring_for_each_cqe(&r0->ring, head, cqe)
        {
            process(0, cqe);
            count++;
        }
        io_uring_cq_advance(&r0->ring, count);
        last = count;
        flush_pass();
        if (accept_ring < 0 && rings[0].used + 256 < rings[0].nslots) arm_accept(0); /* table had filled up */
        sweep();
    }
}
