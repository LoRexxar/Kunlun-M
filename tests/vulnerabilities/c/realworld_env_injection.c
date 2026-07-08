/**
 * realworld_env_injection.c
 *
 * Simulates a simple deployment CLI tool ("deployctl") that configures
 * runtime environment variables based on user input. Demonstrates
 * environment variable injection vulnerabilities.
 *
 * VULN patterns: setenv()/putenv() with user-controlled input (no validation)
 * SAFE patterns: validate/sanitize input before setting environment variables
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_ENV_KEY_LEN 64
#define MAX_ENV_VAL_LEN 1024

/**
 * Check if an environment variable name is safe.
 * Returns 1 if safe, 0 if dangerous.
 */
static int is_safe_env_key(const char *key) {
    if (!key || strlen(key) == 0 || strlen(key) > MAX_ENV_KEY_LEN) {
        return 0;
    }
    /* Environment variable names must start with letter or underscore,
       and contain only alphanumeric + underscore */
    if (!(isalpha((unsigned char)key[0]) || key[0] == '_')) {
        return 0;
    }
    for (size_t i = 0; i < strlen(key); i++) {
        char c = key[i];
        if (!(isalnum((unsigned char)c) || c == '_')) {
            return 0;
        }
    }
    return 1;
}

/**
 * Check if an environment variable value is safe.
 * Returns 1 if safe, 0 if potentially dangerous.
 */
static int is_safe_env_value(const char *value) {
    if (!value || strlen(value) > MAX_ENV_VAL_LEN) {
        return 0;
    }
    /* Reject values containing shell metacharacters or newlines */
    const char *dangerous_chars = "|&;$`\\\"\n\r";
    if (strpbrk(value, dangerous_chars) != NULL) {
        return 0;
    }
    return 1;
}

/**
 * Safely set a deployment environment variable.
 * SAFE: validates both key name and value before calling setenv().
 */
void safe_set_deploy_env(const char *key, const char *value) {
    if (!key || !value) return;

    /* SAFE: Validate key name */
    if (!is_safe_env_key(key)) {
        fprintf(stderr, "Error: invalid environment variable name '%s'\n", key);
        return;
    }

    /* SAFE: Validate value */
    if (!is_safe_env_value(value)) {
        fprintf(stderr, "Error: invalid environment variable value\n");
        return;
    }

    /* SAFE: Both validated — safe to set */
    setenv(key, value, 1);
    printf("Set %s=%s (safe)\n", key, value);
}

/**
 * Set the application mode from command-line argument.
 * VULN: setenv() with argv[1] as value — no validation.
 *       Attacker can inject "prod; export PATH=/tmp/evil:$PATH"
 *       which may be interpreted by downstream shell scripts.
 */
void vuln_set_app_mode(const char *mode) {
    /* VULN: Environment variable injection — unsanitized user input in setenv */
    setenv("APP_MODE", mode, 1);
    printf("App mode set to: %s\n", mode);
}

/**
 * Set the database connection string from command-line argument.
 * VULN: setenv() with argv[2] as value — no validation.
 *       Attacker can inject malicious connection strings or shell commands.
 */
void vuln_set_db_conn(const char *conn_string) {
    /* VULN: Environment variable injection — unsanitized user input in setenv */
    setenv("DB_CONNECTION", conn_string, 1);
    printf("DB connection set to: %s\n", conn_string);
}

/**
 * Set environment variable from user input using putenv.
 * VULN: putenv() with argv-derived string — no validation.
 *       Attacker can pass "LD_PRELOAD=/tmp/evil.so" or "PATH=/tmp".
 */
void vuln_set_raw_env(const char *env_string) {
    /* putenv takes ownership — we need a mutable copy */
    char *env_copy = strdup(env_string);
    if (!env_copy) return;

    /* VULN: Environment variable injection — unsanitized user input in putenv */
    putenv(env_copy);
    printf("Environment set: %s\n", env_string);
}

/**
 * Set environment from a user-provided key and value.
 * VULN: setenv() with argv-derived key — no validation on key name.
 *       Attacker can pass "LD_PRELOAD" as key to inject library loading.
 */
void vuln_set_env_pair(const char *key, const char *value) {
    /* VULN: Environment variable injection — unsanitized key name in setenv */
    setenv(key, value, 1);
    printf("Set %s=%s (vulnerable)\n", key, value);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <app_mode> [db_conn_string] [env_key=value]\n", argv[0]);
        return 1;
    }

    printf("=== Deployctl Deployment Tool ===\n\n");

    /* VULN: setenv with unsanitized argv value */
    vuln_set_app_mode(argv[1]);

    printf("\n");

    /* VULN: setenv with unsanitized argv value */
    if (argc >= 3) {
        vuln_set_db_conn(argv[2]);
    }

    printf("\n");

    /* VULN: setenv with unsanitized argv key */
    if (argc >= 4) {
        /* Parse "KEY=VALUE" format */
        char *eq = strchr(argv[3], '=');
        if (eq) {
            *eq = '\0';
            vuln_set_env_pair(argv[3], eq + 1);
            *eq = '=';  /* Restore */
        }
    }

    printf("\n");

    /* VULN: putenv with unsanitized argv value */
    if (argc >= 5) {
        vuln_set_raw_env(argv[4]);
    }

    printf("\n--- Safe alternatives ---\n\n");

    /* SAFE: setenv with validated key and value */
    safe_set_deploy_env("APP_MODE_SAFE", argv[1]);

    /* SAFE: setenv with validated key and value */
    if (argc >= 3) {
        safe_set_deploy_env("DB_CONN_SAFE", argv[2]);
    }

    return 0;
}
