/**
 * realworld_format_string.c
 *
 * Simulates a simple logging CLI tool ("logview") that formats
 * and displays log entries. Accepts user-provided format strings
 * and log messages via command-line arguments.
 *
 * VULN patterns: printf/fprintf/sprintf with user input as format string
 * SAFE patterns: printf with "%s" literal format specifier
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_MSG_LEN 512
#define MAX_LOG_LINE 1024

/**
 * Log a message to a file with a safe fixed format.
 * SAFE: uses "%s" as the format string, argv[1] is the data argument.
 */
void safe_log_message(FILE *logfp, const char *message) {
    if (!logfp || !message) return;
    /* SAFE: format string is a literal "%s", user input is data only */
    fprintf(logfp, "[LOG] %s\n", message);
}

/**
 * Format a log entry into a buffer safely.
 * SAFE: uses "%s" literal format specifier, user input is data only.
 */
void safe_format_entry(char *buf, size_t buflen, const char *entry) {
    if (!buf || !entry) return;
    /* SAFE: format string is a literal, user input is data only */
    snprintf(buf, buflen, "ENTRY: %s", entry);
}

/**
 * Print a greeting message to stdout.
 * VULN: printf() with user-controlled argv[1] as the format string.
 *       If argv[1] contains "%s%s%s%s%n%n%n%n" or "%x%x%x%x%x",
 *       it can leak stack data or cause segfaults.
 */
void vuln_print_greeting(const char *user_input) {
    /* VULN: Format string vulnerability — user input used as format string */
    printf(user_input);
    printf("\n");
}

/**
 * Log a user event to a file.
 * VULN: fprintf() with argv[2] as the format string.
 *       Can read/write arbitrary memory via %n, leak stack via %x.
 */
void vuln_log_event(FILE *logfp, const char *user_format) {
    if (!logfp || !user_format) return;
    /* VULN: Format string vulnerability — user input used as format string in fprintf */
    fprintf(logfp, user_format);
    fprintf(logfp, "\n");
}

/**
 * Format a response string into a buffer.
 * VULN: sprintf() with argv[1] as the format string.
 *       User input like "%999999999d" can cause a stack buffer overflow,
 *       or "%n" can overwrite memory.
 */
void vuln_format_response(char *buf, const char *user_format) {
    if (!buf || !user_format) return;
    /* VULN: Format string vulnerability — user input used as format string in sprintf */
    sprintf(buf, user_format);
}

int main(int argc, char *argv[]) {
    char log_buffer[MAX_LOG_LINE];
    char format_buffer[MAX_MSG_LEN];

    if (argc < 2) {
        printf("Usage: %s <message> [log_format]\n", argv[0]);
        return 1;
    }

    /* Open a log file for writing */
    FILE *logfp = fopen("/tmp/logview.log", "a");
    if (!logfp) {
        fprintf(stderr, "Warning: could not open log file\n");
    }

    printf("=== Logview Log Formatting Tool ===\n\n");

    /* VULN: printf with user-controlled format string from argv[1] */
    vuln_print_greeting(argv[1]);

    /* VULN: sprintf with user-controlled format string from argv[1] */
    vuln_format_response(format_buffer, argv[1]);
    printf("Formatted response: %s\n", format_buffer);

    /* VULN: fprintf with user-controlled format string from argv[2] */
    if (argc >= 3 && logfp) {
        vuln_log_event(logfp, argv[2]);
    }

    /* SAFE: fprintf with literal format string, user input as data */
    if (logfp) {
        safe_log_message(logfp, argv[1]);
    }

    /* SAFE: snprintf with literal format string, user input as data */
    safe_format_entry(log_buffer, sizeof(log_buffer), argv[1]);
    printf("Log entry: %s\n", log_buffer);

    /* SAFE: printf with literal "%s" format string */
    printf("User message: %s\n", argv[1]);

    if (logfp) {
        fclose(logfp);
    }

    return 0;
}
