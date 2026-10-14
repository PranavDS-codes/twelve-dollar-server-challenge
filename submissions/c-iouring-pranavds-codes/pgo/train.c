/* SQLite PGO training: builds a synthetic database with the challenge schema (no seed data) and runs
 * the server's statements against it. Only the profile is kept; this program is not shipped. */
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static sqlite3 *db;
static void ex(const char *sql)
{
    char *err;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) { fprintf(stderr, "train: %s\n", err); exit(1); }
}
static sqlite3_stmt *prep(const char *sql)
{
    sqlite3_stmt *s;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK) { fprintf(stderr, "train: %s\n", sqlite3_errmsg(db)); exit(1); }
    return s;
}
static void run(sqlite3_stmt *s) { while (sqlite3_step(s) == SQLITE_ROW) {} sqlite3_reset(s); }

int main(void)
{
    unlink("train.db"); unlink("train.db-wal"); unlink("train.db-shm");
    if (sqlite3_open("train.db", &db) != SQLITE_OK) return 1;
    ex("PRAGMA journal_mode=WAL; PRAGMA synchronous=OFF;"
       "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE,"
       " created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')));"
       "CREATE TABLE posts (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),"
       " body TEXT NOT NULL CHECK (length(body) BETWEEN 1 AND 500),"
       " created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')));"
       "CREATE TABLE likes (user_id INTEGER NOT NULL REFERENCES users(id), post_id INTEGER NOT NULL REFERENCES posts(id),"
       " created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')), PRIMARY KEY (user_id, post_id));"
       "CREATE INDEX posts_created_at_id_idx ON posts (created_at DESC, id DESC);"
       "CREATE INDEX posts_user_id_idx ON posts (user_id); CREATE INDEX likes_post_id_idx ON likes (post_id);"
       "BEGIN;"
       "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 10000)"
       " INSERT INTO users(id, username) SELECT i, 'user_' || i FROM n;"
       "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 100000)"
       " INSERT INTO posts(id, user_id, body, created_at) SELECT i, 1 + i % 10000, 'post number ' || i || ' says \"hi\"',"
       " strftime('%Y-%m-%dT%H:%M:%fZ', 1700000000 + i * 60, 'unixepoch') FROM n;"
       "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 400000)"
       " INSERT OR IGNORE INTO likes(user_id, post_id) SELECT 1 + (i * 7919) % 10000, 1 + (i * 104729) % 100000 FROM n;"
       "COMMIT; PRAGMA synchronous=NORMAL; PRAGMA locking_mode=EXCLUSIVE; PRAGMA foreign_keys=ON;"
       "PRAGMA mmap_size=268435456; PRAGMA wal_autocheckpoint=0;");
    const char *cols = "SELECT p.id, p.body, p.created_at, u.username, (SELECT count(*) FROM likes l WHERE l.post_id = p.id) FROM posts p JOIN users u ON u.id = p.user_id ";
    char sql[512];
    snprintf(sql, sizeof sql, "%sORDER BY p.created_at DESC, p.id DESC LIMIT 20", cols);
    sqlite3_stmt *feed_ref = prep(sql);
    snprintf(sql, sizeof sql, "%sWHERE p.id = ?1", cols);
    sqlite3_stmt *post = prep(sql);
    sqlite3_stmt *ids = prep("SELECT id FROM posts ORDER BY created_at DESC, id DESC LIMIT 20");
    sqlite3_stmt *rows = prep("SELECT p.id, p.body, p.created_at, u.username FROM posts p JOIN users u ON u.id = p.user_id WHERE p.id BETWEEN ?1 AND ?2");
    sqlite3_stmt *likes = prep("SELECT post_id, count(*) FROM likes WHERE post_id BETWEEN ?1 AND ?2 GROUP BY post_id");
    sqlite3_stmt *create = prep("INSERT INTO posts (user_id, body) VALUES (?1, ?2) RETURNING id, created_at");
    sqlite3_stmt *like = prep("INSERT INTO likes (user_id, post_id) SELECT ?1, ?2 WHERE EXISTS (SELECT 1 FROM posts WHERE id = ?2) ON CONFLICT (user_id, post_id) DO NOTHING");
    sqlite3_stmt *exists = prep("SELECT 1 FROM posts WHERE id = ?1");
    sqlite3_stmt *begin = prep("BEGIN"), *commit = prep("COMMIT");
    unsigned x = 12345;
    for (int round = 0; round < 4000; round++) {
        run(begin);
        for (int k = 0; k < 10; k++) {
            int64_t top = 0;
            while (sqlite3_step(ids) == SQLITE_ROW) top = sqlite3_column_int64(ids, 0);
            sqlite3_reset(ids);
            sqlite3_bind_int64(rows, 1, top); sqlite3_bind_int64(rows, 2, top + 19); run(rows);
            sqlite3_bind_int64(likes, 1, top); sqlite3_bind_int64(likes, 2, top + 19); run(likes);
            x = x * 1103515245 + 12345;
            sqlite3_bind_int64(post, 1, 1 + x % 100000); run(post);
            sqlite3_bind_int64(post, 1, top); run(post);
        }
        if (round % 50 == 0) run(feed_ref);
        x = x * 1103515245 + 12345;
        sqlite3_bind_int64(like, 1, 1 + x % 10000); sqlite3_bind_int64(like, 2, 1 + (x >> 8) % 100000); run(like);
        if (sqlite3_changes(db) == 0) { sqlite3_bind_int64(exists, 1, 1 + (x >> 8) % 100000); run(exists); }
        if (round % 8 == 0) {
            sqlite3_bind_int64(create, 1, 1 + x % 10000);
            sqlite3_bind_text(create, 2, "training post body with some text", -1, SQLITE_STATIC);
            run(create);
        }
        run(commit);
        if (round % 500 == 0) sqlite3_wal_checkpoint_v2(db, NULL, SQLITE_CHECKPOINT_PASSIVE, NULL, NULL);
    }
    sqlite3_close(db);
    unlink("train.db"); unlink("train.db-wal"); unlink("train.db-shm");
    return 0;
}
