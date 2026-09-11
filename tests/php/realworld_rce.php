<?php
/**
 * Real-world Command Injection (RCE) test file for Kunlun-M scanner.
 * Simulates a server admin panel with system management features.
 */

class SystemAdminController {
    private $logDir = '/var/log/app';

    /**
     * VULN: Command injection via $_GET['host'] concatenated into shell command.
     * Attacker can inject: 127.0.0.1; cat /etc/passwd
     */
    public function pingHost() {
        $host = $_GET['host'] ?? 'localhost';
        $output = shell_exec("ping -c 4 " . $host . " 2>&1");
        echo "<pre>Ping results:\n" . htmlspecialchars($output, ENT_QUOTES, 'UTF-8') . "</pre>";
        // Taint source: $_GET['host'] -> Sink: shell_exec() concatenation
    }

    /**
     * VULN: Command injection via $_POST['domain'] in system() call.
     * Attacker can inject: example.com && rm -rf /
     */
    public function lookupDns() {
        $domain = $_POST['domain'] ?? '';
        if (empty($domain)) {
            echo "Please provide a domain.";
            return;
        }
        echo "<pre>";
        system("dig " . $domain . " +short 2>&1");
        echo "</pre>";
        // Taint source: $_POST['domain'] -> Sink: system() concatenation
    }

    /**
     * VULN: Command injection via $_REQUEST['file'] in exec().
     * Attacker can inject: access.log; whoami
     */
    public function tailLog() {
        $file = $_REQUEST['file'] ?? 'app.log';
        $fullPath = $this->logDir . '/' . $file;
        $lines = (int)($_REQUEST['lines'] ?? 50);

        exec("tail -n {$lines} " . $fullPath . " 2>&1", $output, $returnCode);
        echo "<h3>Log Output (last {$lines} lines):</h3><pre>";
        echo htmlspecialchars(implode("\n", $output), ENT_QUOTES, 'UTF-8');
        echo "</pre>";
        // Taint source: $_REQUEST['file'] -> Sink: exec() concatenation
    }

    /**
     * SAFE: Using escapeshellarg() to properly escape user input.
     */
    public function safePing() {
        $host = $_GET['host'] ?? 'localhost';
        $escapedHost = escapeshellarg($host);
        $output = shell_exec("ping -c 4 " . $escapedHost . " 2>&1");
        echo "<pre>Ping results:\n" . htmlspecialchars($output, ENT_QUOTES, 'UTF-8') . "</pre>";
        // Safe: escapeshellarg() prevents command injection
    }

    /**
     * SAFE: Using escapeshellcmd() + escapeshellarg() with strict validation.
     */
    public function safeDnsLookup() {
        $domain = $_POST['domain'] ?? '';
        // Validate domain format first
        if (!preg_match('/^[a-zA-Z0-9][a-zA-Z0-9\-\.]{1,253}[a-zA-Z0-9]$/', $domain)) {
            echo "Invalid domain format.";
            return;
        }
        $escapedDomain = escapeshellarg($domain);
        echo "<pre>";
        system("dig " . $escapedDomain . " +short 2>&1");
        echo "</pre>";
        // Safe: regex validation + escapeshellarg()
    }

    /**
     * SAFE: Whitelist approach for log files.
     */
    public function safeTailLog() {
        $file = $_REQUEST['file'] ?? 'app.log';
        $allowedFiles = ['app.log', 'error.log', 'access.log', 'debug.log'];

        if (!in_array($file, $allowedFiles, true)) {
            echo "Invalid log file requested.";
            return;
        }

        $lines = (int)($_REQUEST['lines'] ?? 50);
        $lines = min(max($lines, 1), 1000); // Clamp range

        $fullPath = escapeshellarg($this->logDir . '/' . $file);
        $linesArg = escapeshellarg((string)$lines);
        exec("tail -n {$linesArg} {$fullPath} 2>&1", $output, $returnCode);
        echo "<h3>Log Output:</h3><pre>";
        echo htmlspecialchars(implode("\n", $output), ENT_QUOTES, 'UTF-8');
        echo "</pre>";
        // Safe: whitelist + range clamping + escapeshellarg()
    }
}

// --- Routing ---
if (php_sapi_name() !== 'cli') {
    $controller = new SystemAdminController();
    $action = $_GET['action'] ?? 'pingHost';
    if (method_exists($controller, $action)) {
        $controller->$action();
    }
}
