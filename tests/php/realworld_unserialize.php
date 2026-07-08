<?php
/**
 * Real-world Insecure Deserialization test file for Kunlun-M scanner.
 * Simulates a session handling and cache serialization system.
 */

class SessionController {
    private $cacheDir;

    public function __construct() {
        $this->cacheDir = __DIR__ . '/cache/';
    }

    /**
     * VULN: Insecure deserialization via $_COOKIE containing serialized data.
     * Attacker can craft malicious serialized PHP objects.
     */
    public function loadSession() {
        $sessionData = $_COOKIE['session_data'] ?? '';
        if (empty($sessionData)) {
            echo json_encode(['error' => 'No session data']);
            return;
        }

        $session = unserialize($sessionData);
        if ($session === false) {
            echo json_encode(['error' => 'Invalid session']);
            return;
        }

        echo json_encode([
            'user_id'  => $session['user_id'] ?? null,
            'username' => $session['username'] ?? 'guest',
            'role'     => $session['role'] ?? 'visitor',
        ]);
        // Taint source: $_COOKIE['session_data'] -> Sink: unserialize()
        // Attacker can inject POP chain payloads
    }

    /**
     * VULN: Insecure deserialization via $_POST with serialized cache data.
     * Attacker can use gadget chains in popular libraries.
     */
    public function restoreCache() {
        $cacheBlob = $_POST['cache_data'] ?? '';
        if (empty($cacheBlob)) {
            echo json_encode(['error' => 'No cache data provided']);
            return;
        }

        // Base64 decoded then unserialized - still vulnerable
        $decoded = base64_decode($cacheBlob);
        if ($decoded === false) {
            echo json_encode(['error' => 'Invalid base64']);
            return;
        }

        $cache = unserialize($decoded);
        if ($cache === false) {
            echo json_encode(['error' => 'Failed to unserialize']);
            return;
        }

        // Cache object may contain malicious POP chain objects
        echo json_encode(['restored' => true, 'keys' => array_keys((array)$cache)]);
        // Taint source: $_POST['cache_data'] -> Sink: unserialize() (via base64_decode)
    }

    /**
     * VULN: Insecure deserialization via $_REQUEST['state'] parameter.
     */
    public function loadAppState() {
        $state = $_REQUEST['state'] ?? '';
        if (empty($state)) {
            echo json_encode(['error' => 'No state data']);
            return;
        }

        $appState = @unserialize(urldecode($state));
        if ($appState === false) {
            echo json_encode(['error' => 'Corrupt state']);
            return;
        }

        // Using object properties without checking type
        foreach ($appState as $key => $value) {
            if (is_object($value)) {
                // Dangerous: may invoke __toString() or __destruct() on malicious objects
                echo "<div>{$key}: " . (string)$value . "</div>";
            } else {
                echo "<div>{$key}: " . htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8') . "</div>";
            }
        }
        // Taint source: $_REQUEST['state'] -> Sink: unserialize() (via urldecode)
    }

    /**
     * SAFE: Using json_encode/json_decode instead of serialize/unserialize.
     * JSON doesn't support objects, preventing gadget chain attacks.
     */
    public function safeLoadSession() {
        $sessionData = $_COOKIE['session_data'] ?? '';
        if (empty($sessionData)) {
            echo json_encode(['error' => 'No session data']);
            return;
        }

        // Use JSON instead of PHP serialization
        $session = json_decode($sessionData, true);
        if ($session === null && json_last_error() !== JSON_ERROR_NONE) {
            echo json_encode(['error' => 'Invalid session data']);
            return;
        }

        // Validate expected structure
        $userId  = $session['user_id'] ?? null;
        $name    = $session['username'] ?? 'guest';

        if (!is_int($userId) && !is_string($userId)) {
            $userId = null;
        }

        echo json_encode([
            'user_id'  => $userId,
            'username' => is_string($name) ? $name : 'guest',
        ]);
        // Safe: JSON doesn't support PHP object serialization / POP chains
    }

    /**
     * SAFE: Using allowed_classes option in unserialize (PHP 7.0+).
     */
    public function safeRestoreCache() {
        $cacheBlob = $_POST['cache_data'] ?? '';
        if (empty($cacheBlob)) {
            echo json_encode(['error' => 'No cache data']);
            return;
        }

        $decoded = base64_decode($cacheBlob);
        if ($decoded === false) {
            echo json_encode(['error' => 'Invalid base64']);
            return;
        }

        // Restrict to only specific safe classes (or no classes at all)
        $options = ['allowed_classes' => false]; // Disallow all objects
        $cache = unserialize($decoded, $options);
        if ($cache === false) {
            echo json_encode(['error' => 'Failed to unserialize']);
            return;
        }

        echo json_encode(['restored' => true, 'data' => $cache]);
        // Safe: allowed_classes=false prevents any object instantiation from unserialized data
    }
}

// --- Routing ---
if (php_sapi_name() !== 'cli') {
    $controller = new SessionController();
    $action = $_GET['action'] ?? 'loadSession';
    if (method_exists($controller, $action)) {
        $controller->$action();
    }
}
