/**
 * realworld_buffer_overflow.c
 *
 * Simulates a simple user management CLI tool ("useradm") that
 * processes usernames and descriptions from command-line arguments.
 * Demonstrates dangerous string functions vs. safe bounded alternatives.
 *
 * VULN patterns: strcpy/strcat/gets with no length checking
 * SAFE patterns: strncpy/snprintf with explicit size limits
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_USERNAME 32
#define MAX_BIO 128
#define MAX_PATH 256

/**
 * Safely copy a username into a fixed-size buffer.
 * SAFE: uses strncpy with explicit size limit.
 */
void safe_copy_username(char *dest, size_t dest_size, const char *src) {
    if (!dest || !src) return;
    /* SAFE: strncpy with size limit prevents buffer overflow */
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
}

/**
 * Safely build a full path from directory and filename.
 * SAFE: uses snprintf with buffer size limit.
 */
void safe_build_path(char *dest, size_t dest_size, const char *dir, const char *file) {
    if (!dest || !dir || !file) return;
    /* SAFE: snprintf with size limit prevents buffer overflow */
    snprintf(dest, dest_size, "%s/%s", dir, file);
}

/**
 * Copy a username from command-line argument into a fixed buffer.
 * VULN: strcpy() with no length check — if argv[1] is longer than
 *       MAX_USERNAME (32) bytes, it overflows the stack buffer.
 */
void vuln_set_username(char *buffer, const char *username) {
    if (!buffer || !username) return;
    /* VULN: Buffer overflow via strcpy with no bounds checking */
    strcpy(buffer, username);
}

/**
 * Append a description to a user bio field.
 * VULN: strcat() with no length check — repeated calls can overflow.
 */
void vuln_append_bio(char *bio, const char *additional_text) {
    if (!bio || !additional_text) return;
    /* VULN: Buffer overflow via strcat with no bounds checking */
    strcat(bio, additional_text);
}

/**
 * Build a file path from user-provided directory and filename.
 * VULN: strcat() with no length check — long paths overflow the buffer.
 */
void vuln_build_filepath(char *path, const char *directory, const char *filename) {
    if (!path || !directory || !filename) return;
    /* VULN: Buffer overflow via strcpy + strcat with no bounds checking */
    strcpy(path, directory);
    strcat(path, "/");
    strcat(path, filename);
}

int main(int argc, char *argv[]) {
    char username[MAX_USERNAME];
    char bio[MAX_BIO];
    char user_path[MAX_PATH];

    if (argc < 3) {
        printf("Usage: %s <username> <bio_text>\n", argv[0]);
        return 1;
    }

    printf("=== Useradm User Management Tool ===\n\n");

    /* Initialize bio */
    bio[0] = '\0';

    /* VULN: strcpy overflow — argv[1] longer than 32 bytes overflows username buffer */
    vuln_set_username(username, argv[1]);
    printf("Username set to: %s\n", username);

    /* VULN: strcat overflow — argv[2] longer than 128 bytes overflows bio buffer */
    vuln_append_bio(bio, argv[2]);
    printf("Bio set to: %s\n", bio);

    /* VULN: strcpy + strcat overflow — long argv[1] overflows user_path buffer */
    vuln_build_filepath(user_path, "/home/users", argv[1]);
    printf("User path: %s\n", user_path);

    printf("\n--- Safe operations ---\n\n");

    /* SAFE: strncpy with size limit */
    char safe_username[MAX_USERNAME];
    safe_copy_username(safe_username, sizeof(safe_username), argv[1]);
    printf("Safe username: %s\n", safe_username);

    /* SAFE: snprintf with size limit */
    char safe_path[MAX_PATH];
    safe_build_path(safe_path, sizeof(safe_path), "/home/users", argv[1]);
    printf("Safe user path: %s\n", safe_path);

    return 0;
}
