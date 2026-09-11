/**
 * realworld_file_write.c
 *
 * Simulates a simple configuration backup CLI tool ("cfgbackup") that
 * writes configuration data to user-specified file paths. Demonstrates
 * arbitrary file write vulnerabilities and safe alternatives.
 *
 * VULN patterns: fopen("w") with user-controlled path (no sanitization)
 * SAFE patterns: realpath() resolution + prefix check before file open
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#define BACKUP_DIR "/var/cfgbackup"
#define MAX_PATH_LEN 4096
#define MAX_DATA_LEN 4096

/**
 * Safely write backup data to a file after validating the path.
 * SAFE: resolves real path and checks it stays within BACKUP_DIR.
 */
void safe_write_backup(const char *user_path, const char *data) {
    if (!user_path || !data) return;

    char resolved_path[PATH_MAX];
    char full_path[MAX_PATH_LEN];

    snprintf(full_path, sizeof(full_path), "%s/%s", BACKUP_DIR, user_path);

    /* SAFE: Use realpath to resolve symlinks and canonicalize */
    char *real = realpath(full_path, resolved_path);
    if (!real) {
        /* File might not exist yet; resolve the parent directory instead */
        char *last_slash = strrchr(full_path, '/');
        if (last_slash) {
            char parent[MAX_PATH_LEN];
            size_t parent_len = (size_t)(last_slash - full_path);
            strncpy(parent, full_path, parent_len);
            parent[parent_len] = '\0';

            char parent_resolved[PATH_MAX];
            char *parent_real = realpath(parent, parent_resolved);
            if (!parent_real || strncmp(parent_real, BACKUP_DIR, strlen(BACKUP_DIR)) != 0) {
                fprintf(stderr, "Error: path traversal detected — write denied\n");
                return;
            }
            /* Parent is safe, proceed with full_path */
            strncpy(resolved_path, full_path, sizeof(resolved_path) - 1);
            resolved_path[sizeof(resolved_path) - 1] = '\0';
        } else {
            fprintf(stderr, "Error: invalid path '%s'\n", user_path);
            return;
        }
    } else {
        /* SAFE: Verify the resolved path starts with the backup directory */
        if (strncmp(real, BACKUP_DIR, strlen(BACKUP_DIR)) != 0) {
            fprintf(stderr, "Error: path traversal detected — write denied\n");
            return;
        }
    }

    /* SAFE: Path validated, now open for writing */
    FILE *fp = fopen(resolved_path, "w");
    if (!fp) {
        fprintf(stderr, "Error: cannot create '%s'\n", resolved_path);
        return;
    }
    fputs(data, fp);
    fclose(fp);
    printf("Backup written safely to '%s'\n", user_path);
}

/**
 * Write configuration backup to a user-specified file path.
 * VULN: fopen("w") with argv-derived path — no sanitization.
 *       User can pass "../../etc/crontab" to overwrite system files.
 */
void vuln_write_backup(const char *user_path, const char *data) {
    char full_path[MAX_PATH_LEN];
    snprintf(full_path, sizeof(full_path), "%s/%s", BACKUP_DIR, user_path);

    /* VULN: Arbitrary file write — no path validation before fopen */
    FILE *fp = fopen(full_path, "w");
    if (!fp) {
        fprintf(stderr, "Error: cannot create '%s'\n", full_path);
        return;
    }
    fputs(data, fp);
    fclose(fp);
    printf("Backup written to '%s'\n", full_path);
}

/**
 * Write a log file to a user-specified directory.
 * VULN: fopen("w") with argv-derived directory — no sanitization.
 *       User can pass "../../tmp/" to write to arbitrary directories.
 */
void vuln_write_log(const char *user_dir, const char *log_content) {
    char full_path[MAX_PATH_LEN];
    snprintf(full_path, sizeof(full_path), "%s/app.log", user_dir);

    /* VULN: Arbitrary file write — no path validation before fopen */
    FILE *fp = fopen(full_path, "w");
    if (!fp) {
        fprintf(stderr, "Error: cannot create '%s'\n", full_path);
        return;
    }
    fputs(log_content, fp);
    fclose(fp);
    printf("Log written to '%s'\n", full_path);
}

/**
 * Overwrite a config file specified by environment variable.
 * VULN: fopen("w") with getenv-derived path — no sanitization.
 *       Attacker sets CONFIG_OUTPUT to "/etc/shadow" or similar.
 */
void vuln_write_config_from_env(const char *config_data) {
    const char *output_path = getenv("CONFIG_OUTPUT");
    if (!output_path) {
        fprintf(stderr, "CONFIG_OUTPUT not set\n");
        return;
    }

    /* VULN: Arbitrary file write — getenv path used directly in fopen */
    FILE *fp = fopen(output_path, "w");
    if (!fp) {
        fprintf(stderr, "Error: cannot create '%s'\n", output_path);
        return;
    }
    fputs(config_data, fp);
    fclose(fp);
    printf("Config written to '%s'\n", output_path);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <output_filename> [data]\n", argv[0]);
        printf("Environment: CONFIG_OUTPUT=<path> for config export\n");
        return 1;
    }

    const char *filename = argv[1];
    const char *data = (argc >= 3) ? argv[2] : "default backup data\n";

    printf("=== Cfgbackup Configuration Backup Tool ===\n\n");

    /* VULN: fopen("w") with unsanitized path from argv */
    vuln_write_backup(filename, data);

    printf("\n");

    /* VULN: fopen("w") with unsanitized directory from argv */
    vuln_write_log(argv[1], "Application log entry\n");

    printf("\n");

    /* VULN: fopen("w") with unsanitized path from getenv */
    vuln_write_config_from_env(data);

    printf("\n--- Safe alternative ---\n\n");

    /* SAFE: realpath + prefix check before fopen */
    safe_write_backup(filename, data);

    return 0;
}
