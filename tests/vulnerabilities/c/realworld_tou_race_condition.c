/**
 * realworld_tou_race_condition.c
 *
 * Simulates a simple file access control CLI tool ("acltool") that
 * manages file permissions. Demonstrates Time-of-Check-Time-of-Use
 * (TOCTOU) race condition vulnerabilities and safe alternatives.
 *
 * VULN patterns: access() check followed by open() with user-controlled path
 * SAFE patterns: open() directly with appropriate flags (no separate access check)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <limits.h>

#define BASE_DIR "/var/acltool/data"
#define MAX_PATH_LEN 4096

/**
 * Safely read a file by opening it directly with O_RDONLY.
 * SAFE: uses open() directly without a prior access() check,
 *       avoiding the TOCTOU race condition window entirely.
 */
int safe_read_file(const char *user_path) {
    char full_path[MAX_PATH_LEN];
    snprintf(full_path, sizeof(full_path), "%s/%s", BASE_DIR, user_path);

    /* SAFE: open() directly — no separate access() check, no TOCTOU window */
    int fd = open(full_path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    /* Use fstat to get file size */
    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        return -1;
    }

    /* Read and print contents */
    char *buf = malloc((size_t)st.st_size + 1);
    if (buf) {
        ssize_t n = read(fd, buf, (size_t)st.st_size);
        if (n > 0) {
            buf[n] = '\0';
            printf("File contents (%zd bytes):\n%s\n", n, buf);
        }
        free(buf);
    }

    close(fd);
    return 0;
}

/**
 * Safely write to a file by opening it directly.
 * SAFE: uses open() directly without a prior access() check.
 */
int safe_write_file(const char *user_path, const char *data) {
    char full_path[MAX_PATH_LEN];
    snprintf(full_path, sizeof(full_path), "%s/%s", BASE_DIR, user_path);

    /* SAFE: open() directly — no separate access() check, no TOCTOU window */
    int fd = open(full_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    write(fd, data, strlen(data));
    close(fd);
    printf("Written safely to '%s'\n", user_path);
    return 0;
}

/**
 * Read a file after checking it exists and is readable.
 * VULN: TOCTOU race condition — access() check followed by open().
 *       Between the access() call and the open() call, an attacker
 *       can replace the file with a symlink to /etc/shadow or another
 *       sensitive file, causing the program to read the target file.
 */
int vuln_read_file(const char *user_path) {
    char full_path[MAX_PATH_LEN];
    snprintf(full_path, sizeof(full_path), "%s/%s", BASE_DIR, user_path);

    /* VULN: TOCTOU — access() check creates a race condition window */
    if (access(full_path, R_OK) != 0) {
        fprintf(stderr, "Error: file '%s' not readable\n", full_path);
        return -1;
    }

    /* Attacker can swap file/symlink between access() and open() */
    /* VULN: open() after access() — TOCTOU race condition */
    int fd = open(full_path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    struct stat st;
    fstat(fd, &st);
    char *buf = malloc((size_t)st.st_size + 1);
    if (buf) {
        ssize_t n = read(fd, buf, (size_t)st.st_size);
        if (n > 0) {
            buf[n] = '\0';
            printf("File contents (%zd bytes):\n%s\n", n, buf);
        }
        free(buf);
    }

    close(fd);
    return 0;
}

/**
 * Write to a file after checking the path is writable.
 * VULN: TOCTOU race condition — access() check followed by open() with O_WRONLY.
 *       Between check and use, an attacker can replace the file with a symlink
 *       to overwrite arbitrary files (e.g., /etc/passwd).
 */
int vuln_write_file(const char *user_path, const char *data) {
    char full_path[MAX_PATH_LEN];
    snprintf(full_path, sizeof(full_path), "%s/%s", BASE_DIR, user_path);

    /* VULN: TOCTOU — access() check creates a race condition window */
    if (access(full_path, W_OK) != 0) {
        fprintf(stderr, "Error: path '%s' not writable\n", full_path);
        return -1;
    }

    /* Attacker can swap file/symlink between access() and open() */
    /* VULN: open() with O_WRONLY after access() — TOCTOU race condition */
    int fd = open(full_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    write(fd, data, strlen(data));
    close(fd);
    printf("Written to '%s'\n", full_path);
    return 0;
}

/**
 * Append to a log file after checking it exists.
 * VULN: TOCTOU race condition — access(F_OK) followed by open() with O_APPEND.
 *       Attacker can create a symlink between check and open.
 */
int vuln_append_log(const char *user_path, const char *log_entry) {
    char full_path[MAX_PATH_LEN];
    snprintf(full_path, sizeof(full_path), "%s/%s", BASE_DIR, user_path);

    /* VULN: TOCTOU — access() check creates a race condition window */
    if (access(full_path, F_OK) != 0) {
        fprintf(stderr, "Error: file '%s' does not exist\n", full_path);
        return -1;
    }

    /* VULN: open() with O_APPEND after access() — TOCTOU race condition */
    int fd = open(full_path, O_WRONLY | O_APPEND);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    write(fd, log_entry, strlen(log_entry));
    close(fd);
    printf("Appended to '%s'\n", full_path);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <action> <filename> [data]\n", argv[0]);
        printf("Actions: read, write, append\n");
        return 1;
    }

    const char *action = argv[1];
    const char *filename = argv[2];
    const char *data = (argc >= 4) ? argv[3] : "default data\n";

    printf("=== Acltool File Access Control Tool ===\n\n");

    if (strcmp(action, "read") == 0) {
        /* VULN: access() then open() — TOCTOU race condition */
        vuln_read_file(filename);

        printf("\n--- Safe alternative ---\n\n");
        /* SAFE: open() directly without access() check */
        safe_read_file(filename);

    } else if (strcmp(action, "write") == 0) {
        /* VULN: access() then open() — TOCTOU race condition */
        vuln_write_file(filename, data);

        printf("\n--- Safe alternative ---\n\n");
        /* SAFE: open() directly without access() check */
        safe_write_file(filename, data);

    } else if (strcmp(action, "append") == 0) {
        /* VULN: access() then open() — TOCTOU race condition */
        vuln_append_log(filename, data);

    } else {
        printf("Unknown action: %s\n", action);
        return 1;
    }

    return 0;
}
