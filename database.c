// database.c
#include "database.h"
#include <stdio.h>
#include <string.h>

sqlite3 *db = NULL;

// Initialize the DB, create table, seed default user
int db_init(void) {
    if (sqlite3_open("crte.db", &db) != SQLITE_OK) {
        fprintf(stderr, "[-] Failed to open DB: %s\n", sqlite3_errmsg(db));
        return 0;
    }

    const char *sql =
        "CREATE TABLE IF NOT EXISTS users ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  username TEXT UNIQUE,"
        "  password TEXT"
        ");";

    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "[-] Failed to init table: %s\n", err);
        sqlite3_free(err);
        return 0;
    }

    // seed a default user if table is empty
    const char *check_sql = "SELECT COUNT(*) FROM users;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, check_sql, -1, &stmt, NULL) == SQLITE_OK) {
        int rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW) {
            int count = sqlite3_column_int(stmt, 0);
            if (count == 0) {
                const char *seed_sql =
                    "INSERT INTO users (username, password) "
                    "VALUES ('admin', 'password123');";
                char *err2 = NULL;
                if (sqlite3_exec(db, seed_sql, NULL, NULL, &err2) != SQLITE_OK) {
                    fprintf(stderr, "[-] Failed to seed user: %s\n", err2);
                    sqlite3_free(err2);
                } else {
                    printf("[+] Seeded default user: admin / password123\n");
                }
            }
        }
        sqlite3_finalize(stmt);
    }

    return 1;
}

// For our /add-user page: wrapper that reuses the intentionally vulnerable creator
int db_add_user(const char *username, const char *password) {
    return db_create_user(username, password);
}

// Iterate over every user: used by /users page
int db_for_each_user(
    int (*cb)(int id, const char *username, void *udata),
    void *udata
) {
    if (!db) return 0;

    const char *sql = "SELECT id, username FROM users ORDER BY id;";
    sqlite3_stmt *stmt = NULL;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "[-] Failed to query users: %s\n", sqlite3_errmsg(db));
        return 0;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int id = sqlite3_column_int(stmt, 0);
        const unsigned char *u = sqlite3_column_text(stmt, 1);
        const char *username = (const char *)u;

        // If callback returns non-zero, stop early
        if (cb(id, username, udata) != 0) {
            break;
        }
    }

    sqlite3_finalize(stmt);
    return 1;
}

// intentionally vulnerable login (for SQLi demo)
int db_verify_login(const char *username, const char *password) {
    if (!db) return 0;

    char query[512];
    snprintf(query, sizeof(query),
             "SELECT id FROM users "
             "WHERE username='%s' AND password='%s';",
             username, password);

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "[-] prepare failed: %s\n", sqlite3_errmsg(db));
        return 0;
    }

    int rc = sqlite3_step(stmt);
    int ok = (rc == SQLITE_ROW);  // any row means that it's logged in

    sqlite3_finalize(stmt);
    return ok;
}

// intentionally vulnerable user creation (for SQLi demo)
int db_create_user(const char *username, const char *password) {
    if (!db) return 0;

    char query[512];
    snprintf(query, sizeof(query),
             "INSERT INTO users (username, password) "
             "VALUES ('%s', '%s');",
             username, password);

    char *err = NULL;
    if (sqlite3_exec(db, query, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "[-] insert failed: %s\n", err);
        sqlite3_free(err);
        return 0;
    }
    return 1;
}

void db_close(void) {
    if (db) {
        sqlite3_close(db);
        db = NULL;
    }
}
int db_verify_login_safe(const char *username, const char *password) {
    if (!db) return 0;

    const char *sql =
        "SELECT id FROM users WHERE username = ? AND password = ?;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "[-] safe login prepare failed: %s\n", sqlite3_errmsg(db));
        return 0;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, password, -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    int ok = (rc == SQLITE_ROW);

    sqlite3_finalize(stmt);
    return ok;
}

int db_create_user_safe(const char *username, const char *password) {
    if (!db) return 0;

    const char *sql =
        "INSERT INTO users (username, password) VALUES (?, ?);";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "[-] safe insert prepare failed: %s\n", sqlite3_errmsg(db));
        return 0;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, password, -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "[-] safe insert failed: %s\n", sqlite3_errmsg(db));
        return 0;
    }

    return 1;
}
