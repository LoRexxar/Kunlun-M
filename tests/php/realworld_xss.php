<?php
/**
 * Real-world XSS vulnerability test file for Kunlun-M scanner.
 * Simulates a simple page rendering controller with user profile display.
 */

class UserController {
    private $db;

    public function __construct($pdo) {
        $this->db = $pdo;
    }

    /**
     * VULN: Reflected XSS via $_GET parameter directly echoed.
     * User-controlled input flows to echo without sanitization.
     */
    public function searchPage() {
        $query = isset($_GET['q']) ? $_GET['q'] : '';
        echo '<div class="search-results">You searched for: ' . $query . '</div>';
        // Taint source: $_GET['q'] -> Sink: echo (no encoding)
    }

    /**
     * VULN: Reflected XSS via $_POST parameter printed with print().
     */
    public function displayComment() {
        $username = $_POST['username'] ?? 'Anonymous';
        $comment  = $_POST['comment'] ?? '';
        print("<p>Comment by <strong>{$username}</strong>:</p>");
        print("<blockquote>{$comment}</blockquote>");
        // Taint source: $_POST['username'], $_POST['comment'] -> Sink: print()
    }

    /**
     * VULN: Reflected XSS via $_REQUEST in an HTML attribute context.
     */
    public function redirectAfterLogin() {
        $next = $_REQUEST['next_page'] ?? '/dashboard';
        echo '<a href="' . $next . '">Continue to your dashboard</a>';
        // Taint source: $_REQUEST['next_page'] -> Sink: echo (in href attribute)
    }

    /**
     * SAFE: Using htmlspecialchars with ENT_QUOTES for output encoding.
     */
    public function safeSearch() {
        $query = isset($_GET['q']) ? $_GET['q'] : '';
        $escaped = htmlspecialchars($query, ENT_QUOTES, 'UTF-8');
        echo '<div class="search-results">You searched for: ' . $escaped . '</div>';
        // Properly encoded: htmlspecialchars breaks XSS payload
    }

    /**
     * SAFE: Using htmlspecialchars in attribute context.
     */
    public function safeLink() {
        $next = $_REQUEST['next_page'] ?? '/dashboard';
        $allowed = ['/', '/dashboard', '/profile', '/settings'];
        if (in_array($next, $allowed, true)) {
            $escaped = htmlspecialchars($next, ENT_QUOTES, 'UTF-8');
            echo '<a href="' . $escaped . '">Continue</a>';
        } else {
            echo '<a href="/dashboard">Continue</a>';
        }
        // Whitelist + encoding: both defense-in-depth layers
    }
}

// --- Simple routing simulation ---
if (php_sapi_name() !== 'cli') {
    $pdo = new PDO('sqlite::memory:');
    $controller = new UserController($pdo);

    $action = $_GET['action'] ?? 'searchPage';
    if (method_exists($controller, $action)) {
        $controller->$action();
    }
}
