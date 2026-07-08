/**
 * realworld_path_traversal.c
 *
 * Simulates a simple document viewer CLI tool ("docview") that
 * reads files based on user-specified paths. Demonstrates path
 * traversal vulnerabilities and safe alternatives.
 *
 * VULN patterns: fopen/remove/rename with user-controlled path (no sanitization)
 * SAFE patterns: realpath() resolution + prefix check before file operations
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#define BASE_DIR "/var/docview/documents"
#define MAX_PATH_LEN 4096

/**
 * Safely open and display a document after validating its path.
 * SAFE: resolves the real path and checks it stays within BASE_DIR.
 */
void safe_view_document(const char *user_path) {
    if (!user_path) return;

    char resolved_path[PATH_MAX];
    char full_path[MAX_PATH_LEN];

    /* Build the full path */
    snprintf(full_path, sizeof(full_path), "%s/%s", BASE_DIR, user_path);

    /* SAFE: Use realpath to resolve symlinks and check prefix */
    char *real = realpath(full_path, resolved_path);
    if (!real) {
        fprintf(stderr, "Error: cannot resolve path '%s'\n", user_path);
        return;
    }

    /* Verify the resolved path starts with the base directory */
    if (strncmp(real, BASE_DIR, strlen(BASE_DIR)) != 0) {
        fprintf(stderr, "Error: path traversal detected — access denied\n");
        return;
    }

    /* Now safe to open */
    FILE *fp = fopen(real, "r");
    if (!fp) {
        fprintf(stderr, "Error: cannot open '%s'\n", real);
        return;
    }

    printf("Document contents:\n");
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        printf("  %s", line);
    }
    fclose(fp);
}

/**
 * Safely delete a document after validating its path.
 * SAFE: resolves the real path and checks it stays within BASE_DIR.
 */
void safe_delete_document(const char *user_path) {
    if (!user_path) return;

    char resolved_path[PATH_MAX];
    char full_path[MAX_PATH_LEN];

    snprintf(full_path, sizeof(full_path), "%s/%s", BASE_DIR, user_path);

    char *real = realpath(full_path, resolved_path);
    if (!real) {
        fprintf(stderr, "Error: cannot resolve path '%s'\n", user_path);
        return;
    }

    /* SAFE: Verify prefix before remove */
    if (strncmp(real, BASE_DIR, strlen(BASE_DIR)) != 0) {
        fprintf(stderr, "Error: path traversal detected — deletion denied\n");
        return;
    }

    if (remove(real) == 0) {
        printf("Document '%s' deleted successfully\n", user_path);
    } else {
        perror("remove");
    }
}

/**
 * View a document based on user-provided filename.
 * VULN: fopen() with argv-derived path — no sanitization.
 *       User can pass "../../etc/passwd" to read arbitrary files.
 */
void vuln_view_document(const char *user_path) {
    char full_path[MAX_PATH_LEN];
    snprintf(full_path, sizeof(full_path), "%s/%s", BASE_DIR, user_path);

    /* VULN: Path traversal — no validation before fopen */
    FILE *fp = fopen(full_path, "r");
    if (!fp) {
        fprintf(stderr, "Error: cannot open '%s'\n", full_path);
        return;
    }

    printf("Document contents:\n");
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        printf("  %s", line);
    }
    fclose(fp);
}

/**
 * Delete a document based on user-provided filename.
 * VULN: remove() with argv-derived path — no sanitization.
 *       User can pass "../../etc/important_file" to delete arbitrary files.
 */
void vuln_delete_document(const char *user_path) {
    char full_path[MAX_PATH_LEN];
    snprintf(full_path, sizeof(full_path), "%s/%s", BASE_DIR, user_path);

    /* VULN: Path traversal — no validation before remove */
    if (remove(full_path) == 0) {
        printf("Document '%s' deleted\n", user_path);
    } else {
        perror("remove");
    }
}

/**
 * Rename a document based on user-provided old and new filenames.
 * VULN: rename() with argv-derived paths — no sanitization.
 *       User can pass "../../etc/hosts" as old or new name.
 */
void vuln_rename_document(const char *old_name, const char *new_name) {
    char old_path[MAX_PATH_LEN];
    char new_path[MAX_PATH_LEN];

    snprintf(old_path, sizeof(old_path), "%s/%s", BASE_DIR, old_name);
    snprintf(new_path, sizeof(new_path), "%s/%s", BASE_DIR, new_name);

    /* VULN: Path traversal — no validation before rename */
    if (rename(old_path, new_path) == 0) {
        printf("Renamed '%s' to '%s'\n", old_name, new_name);
    } else {
        perror("rename");
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <action> <filename> [new_filename]\n", argv[0]);
        printf("Actions: view, delete, rename\n");
        return 1;
    }

    const char *action = argv[1];
    const char *filename = argv[2];

    printf("=== Docview Document Viewer ===\n\n");

    if (strcmp(action, "view") == 0) {
        /* VULN: fopen with unsanitized path from argv */
        vuln_view_document(filename);

        printf("\n--- Safe alternative ---\n\n");
        /* SAFE: realpath + prefix check before fopen */
        safe_view_document(filename);

    } else if (strcmp(action, "delete") == 0) {
        /* VULN: remove with unsanitized path from argv */
        vuln_delete_document(filename);

        printf("\n--- Safe alternative ---\n\n");
        /* SAFE: realpath + prefix check before remove */
        safe_delete_document(filename);

    } else if (strcmp(action, "rename") == 0 && argc >= 4) {
        /* VULN: rename with unsanitized paths from argv */
        vuln_rename_document(filename, argv[3]);

    } else {
        printf("Unknown action or missing argument\n");
        return 1;
    }

    return 0;
}
