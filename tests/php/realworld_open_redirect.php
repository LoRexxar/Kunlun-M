<?php
/**
 * Real-world Open Redirect test file for Kunlun-M scanner.
 * Simulates login/oauth callback flow with redirect functionality.
 */

class AuthController {
    private $allowedDomains = [
        'example.com',
        'www.example.com',
        'app.example.com',
        'dashboard.example.com',
    ];
    private $trustedRedirects = [
        '/dashboard',
        '/profile',
        '/settings',
        '/home',
        '/account',
    ];

    /**
     * VULN: Open redirect via $_GET['redirect'] in header Location.
     * Attacker can use: ?redirect=https://evil.com/phishing
     */
    public function loginRedirect() {
        $redirect = $_GET['redirect'] ?? '/dashboard';

        // Simulated login check
        $_SESSION['user_id'] = 1;

        // Direct redirect without validation
        header("Location: " . $redirect);
        exit;
        // Taint source: $_GET['redirect'] -> Sink: header("Location:")
    }

    /**
     * VULN: Open redirect via $_POST['next'] in header after form submission.
     * Attacker can submit form with next=https://attacker.com/steal-credentials
     */
    public function postLoginRedirect() {
        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';
        $next     = $_POST['next'] ?? '/dashboard';

        // Simplified auth check
        if (empty($username) || empty($password)) {
            http_response_code(401);
            echo json_encode(['error' => 'Missing credentials']);
            return;
        }

        // Assume auth succeeds
        $_SESSION['user'] = $username;

        header("Location: " . $next);
        exit;
        // Taint source: $_POST['next'] -> Sink: header("Location:")
    }

    /**
     * VULN: Open redirect via $_REQUEST['return_to'] after OAuth flow.
     * Uses urlencode then decode but no URL validation.
     */
    public function oauthCallback() {
        $returnTo = $_REQUEST['return_to'] ?? '/dashboard';

        // The URL was "encoded" but we decode it and trust it
        $decodedReturnTo = urldecode($returnTo);

        // Simulate setting OAuth token
        $_SESSION['oauth_token'] = 'fake_token_' . bin2hex(random_bytes(8));

        header("Location: " . $decodedReturnTo);
        exit;
        // Taint source: $_REQUEST['return_to'] -> Sink: header("Location:")
    }

    /**
     * SAFE: Whitelist-based redirect - only allow known internal paths.
     */
    public function safeLoginRedirect() {
        $redirect = $_GET['redirect'] ?? '/dashboard';

        // Strict whitelist of allowed paths
        if (!in_array($redirect, $this->trustedRedirects, true)) {
            $redirect = '/dashboard';
        }

        header("Location: " . $redirect);
        exit;
        // Safe: whitelist prevents external URL redirects
    }

    /**
     * SAFE: Validate that redirect URL is a relative path starting with /.
     */
    public function safePostLoginRedirect() {
        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';
        $next     = $_POST['next'] ?? '/dashboard';

        if (empty($username) || empty($password)) {
            http_response_code(401);
            echo json_encode(['error' => 'Missing credentials']);
            return;
        }

        // Only allow relative paths starting with /
        if (!preg_match('#^/[a-zA-Z0-9\-_/.]*$#', $next)) {
            $next = '/dashboard';
        }

        // Extra safety: block protocol schemes
        if (stripos($next, '://') !== false || stripos($next, '\\\\') !== false) {
            $next = '/dashboard';
        }

        $_SESSION['user'] = $username;
        header("Location: " . $next);
        exit;
        // Safe: regex validation + protocol scheme check
    }

    /**
     * SAFE: Parse URL and validate domain against whitelist.
     */
    public function safeOauthCallback() {
        $returnTo = $_REQUEST['return_to'] ?? '/dashboard';

        // If it's a relative URL (starts with /), it's safe
        if (preg_match('#^/([a-zA-Z0-9\-_/.]*)$#', $returnTo)) {
            header("Location: " . $returnTo);
            exit;
        }

        // If absolute URL, validate domain
        $parsed = parse_url($returnTo);
        if ($parsed && isset($parsed['host'])) {
            if (in_array($parsed['host'], $this->allowedDomains, true)) {
                header("Location: " . $returnTo);
                exit;
            }
        }

        // Fallback to dashboard
        header("Location: /dashboard");
        exit;
        // Safe: relative path allowed + absolute URL domain whitelist
    }
}

// --- Routing ---
if (php_sapi_name() !== 'cli') {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    $controller = new AuthController();
    $action = $_GET['action'] ?? 'loginRedirect';
    if (method_exists($controller, $action)) {
        $controller->$action();
    }
}
