#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>

extern sqlite3 *db;

int db_init(void);
int db_add_user(const char *username, const char *password);
int db_for_each_user(int (*cb)(int id, const char *username, void *udata),
                     void *udata);
int db_verify_login(const char *username, const char *password);
int db_create_user(const char *username, const char *password);

int db_verify_login_safe(const char *username, const char *password);
int db_create_user_safe(const char *username, const char *password);
void db_close(void);

#endif

