/**
 * realworld_sql_injection.c
 *
 * Simulates a simple user lookup CLI tool ("userlookup") that
 * queries a SQLite database for user records. Demonstrates SQL
 * injection via string concatenation vs. parameterized queries.
 *
 * VULN patterns: sqlite3_exec() with SQL string concatenation of user input
 * SAFE patterns: sqlite3_prepare_v2() with parameterized queries
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#define DB_PATH "/tmp/userlookup.db"
#define MAX_QUERY_LEN 1024

/* Callback for sqlite3_exec — prints query results */
static int query_callback(void *not_used, int argc, char **argv, char **col_names) {
    (void)not_used;
    for (int i = 0; i < argc; i++) {
        printf("%s = %s\n", col_names[i], argv[i] ? argv[i] : "NULL");
    }
    printf("---\n");
    return 0;
}

/**
 * Safely look up a user by username using parameterized query.
 * SAFE: uses sqlite3_prepare_v2 with bound parameter — prevents SQL injection.
 */
void safe_lookup_user(sqlite3 *db, const char *username) {
    if (!db || !username) return;

    const char *sql = "SELECT id, username, email FROM users WHERE username = ?;";
    sqlite3_stmt *stmt;

    /* SAFE: Parameterized query prevents SQL injection */
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);

    printf("Results for '%s' (safe query):\n", username);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        printf("  id=%d, username=%s, email=%s\n",
               sqlite3_column_int(stmt, 0),
               sqlite3_column_text(stmt, 1),
               sqlite3_column_text(stmt, 2));
    }

    sqlite3_finalize(stmt);
}

/**
 * Safely look up users by email prefix using parameterized query.
 * SAFE: uses sqlite3_prepare_v2 with LIKE and bound parameter.
 */
void safe_search_email(sqlite3 *db, const char *email_prefix) {
    if (!db || !email_prefix) return;

    const char *sql = "SELECT id, username, email FROM users WHERE email LIKE ?;";
    sqlite3_stmt *stmt;

    /* SAFE: Parameterized query prevents SQL injection */
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return;
    }

    /* Bind with wildcard appended */
    char pattern[256];
    snprintf(pattern, sizeof(pattern), "%s%%", email_prefix);
    sqlite3_bind_text(stmt, 1, pattern, -1, SQLITE_TRANSIENT);

    printf("Email search results for '%s' (safe query):\n", email_prefix);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        printf("  id=%d, username=%s, email=%s\n",
               sqlite3_column_int(stmt, 0),
               sqlite3_column_text(stmt, 1),
               sqlite3_column_text(stmt, 2));
    }

    sqlite3_finalize(stmt);
}

/**
 * Look up a user by username from command-line argument.
 * VULN: sqlite3_exec() with SQL string built by concatenating argv[1].
 *       User can pass "' OR 1=1 --" to dump all records, or
 *       "'; DROP TABLE users; --" to destroy the table.
 */
void vuln_lookup_user(sqlite3 *db, const char *username) {
    char query[MAX_QUERY_LEN];

    /* VULN: SQL injection — user input concatenated directly into SQL */
    snprintf(query, sizeof(query),
             "SELECT id, username, email FROM users WHERE username = '%s';",
             username);

    printf("Running: %s\n", query);
    sqlite3_exec(db, query, query_callback, NULL, NULL);
}

/**
 * Delete a user by username from command-line argument.
 * VULN: sqlite3_exec() with SQL string built by concatenating argv.
 *       User can pass "' OR 1=1 --" to delete all users.
 */
void vuln_delete_user(sqlite3 *db, const char *username) {
    char query[MAX_QUERY_LEN];

    /* VULN: SQL injection — user input concatenated directly into SQL */
    snprintf(query, sizeof(query),
             "DELETE FROM users WHERE username = '%s';",
             username);

    printf("Running: %s\n", query);
    sqlite3_exec(db, query, NULL, NULL, NULL);
    printf("User '%s' deleted (vulnerable query)\n", username);
}

/**
 * Search users by email from environment variable.
 * VULN: sqlite3_exec() with SQL string built by concatenating getenv().
 *       Attacker sets EMAIL_SEARCH env var to "' UNION SELECT * FROM secrets --"
 */
void vuln_search_by_email(sqlite3 *db) {
    const char *email = getenv("EMAIL_SEARCH");
    if (!email) {
        fprintf(stderr, "EMAIL_SEARCH not set\n");
        return;
    }

    char query[MAX_QUERY_LEN];

    /* VULN: SQL injection — getenv value concatenated directly into SQL */
    snprintf(query, sizeof(query),
             "SELECT id, username, email FROM users WHERE email = '%s';",
             email);

    printf("Running: %s\n", query);
    sqlite3_exec(db, query, query_callback, NULL, NULL);
}

/**
 * Initialize a test database with sample data.
 */
static void init_database(sqlite3 *db) {
    const char *create_sql =
        "CREATE TABLE IF NOT EXISTS users ("
        "  id INTEGER PRIMARY KEY,"
        "  username TEXT NOT NULL,"
        "  email TEXT NOT NULL"
        ");"
        "INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin@example.com');"
        "INSERT OR IGNORE INTO users VALUES (2, 'alice', 'alice@example.com');"
        "INSERT OR IGNORE INTO users VALUES (3, 'bob', 'bob@example.com');";

    sqlite3_exec(db, create_sql, NULL, NULL, NULL);
}

int main(int argc, char *argv[]) {
    sqlite3 *db;

    if (argc < 2) {
        printf("Usage: %s <username>\n", argv[0]);
        printf("Environment: EMAIL_SEARCH=<email> for email search\n");
        return 1;
    }

    /* Open and initialize database */
    int rc = sqlite3_open(DB_PATH, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return 1;
    }
    init_database(db);

    printf("=== Userlookup User Search Tool ===\n\n");

    /* VULN: SQL injection via argv concatenation in SELECT */
    vuln_lookup_user(db, argv[1]);

    printf("\n");

    /* VULN: SQL injection via argv concatenation in DELETE */
    vuln_delete_user(db, argv[1]);

    printf("\n");

    /* VULN: SQL injection via getenv concatenation */
    vuln_search_by_email(db);

    printf("\n--- Safe alternatives ---\n\n");

    /* SAFE: Parameterized query prevents SQL injection */
    safe_lookup_user(db, argv[1]);

    printf("\n");

    /* SAFE: Parameterized query with LIKE prevents SQL injection */
    safe_search_email(db, argv[1]);

    sqlite3_close(db);
    return 0;
}
