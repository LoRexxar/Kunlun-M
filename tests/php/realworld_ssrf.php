<?php
/**
 * Real-world SSRF vulnerability test file for Kunlun-M scanner.
 * Simulates a proxy/fetch service that retrieves external URLs.
 */

class ProxyController {
    private $logger;

    public function __construct($logger = null) {
        $this->logger = $logger ?? new class {
            public function warning($msg) { error_log($msg); }
        };
    }

    /**
     * VULN: SSRF via $_GET['url'] passed directly to cURL.
     * Attacker can specify internal IPs (127.0.0.1, 169.254.169.254 for cloud metadata).
     */
    public function fetchUrl() {
        $url = $_GET['url'] ?? '';

        if (empty($url)) {
            http_response_code(400);
            echo json_encode(['error' => 'Missing url parameter']);
            return;
        }

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error    = curl_error($ch);
        curl_close($ch);

        if ($error) {
            $this->logger->warning("cURL error: {$error}");
            http_response_code(502);
            echo json_encode(['error' => 'Failed to fetch URL']);
        } else {
            header('Content-Type: application/json');
            echo json_encode([
                'status_code' => $httpCode,
                'body'        => $response,
            ]);
        }
        // Taint source: $_GET['url'] -> Sink: curl_setopt CURLOPT_URL
    }

    /**
     * VULN: SSRF via $_POST['api_endpoint'] used in file_get_contents.
     * file_get_contents can access internal resources and cloud metadata.
     */
    public function fetchWebhook() {
        $endpoint = $_POST['api_endpoint'] ?? '';
        if (filter_var($endpoint, FILTER_VALIDATE_URL) === false) {
            echo json_encode(['error' => 'Invalid URL format']);
            return;
        }
        // filter_var only checks format, not that it's a safe destination
        $data = @file_get_contents($endpoint);
        if ($data === false) {
            echo json_encode(['error' => 'Could not reach endpoint']);
        } else {
            echo json_encode(['response' => $data]);
        }
        // Taint source: $_POST['api_endpoint'] -> Sink: file_get_contents()
    }

    /**
     * VULN: SSRF via $_REQUEST['callback_url'] with cURL and FOLLOWLOCATION.
     */
    public function sendCallback() {
        $callbackUrl = $_REQUEST['callback_url'] ?? '';
        $payload = json_encode(['status' => 'completed', 'job_id' => uniqid()]);

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $callbackUrl);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);

        $result = curl_exec($ch);
        curl_close($ch);

        echo json_encode(['callback_sent' => true]);
        // Taint source: $_REQUEST['callback_url'] -> Sink: curl_setopt CURLOPT_URL
    }

    /**
     * SAFE: URL whitelist validation before making outbound request.
     */
    public function safeFetchUrl() {
        $url = $_GET['url'] ?? '';
        $allowedHosts = [
            'api.example.com',
            'cdn.example.com',
            'images.example.com',
        ];

        $parsed = parse_url($url);
        if (!$parsed || !isset($parsed['host'])) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid URL']);
            return;
        }

        if (!in_array($parsed['host'], $allowedHosts, true)) {
            http_response_code(403);
            echo json_encode(['error' => 'Domain not allowed']);
            return;
        }

        // Also block private IP ranges
        $ip = gethostbyname($parsed['host']);
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            http_response_code(403);
            echo json_encode(['error' => 'Private/reserved IP not allowed']);
            return;
        }

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        $response = curl_exec($ch);
        curl_close($ch);

        echo json_encode(['body' => $response]);
        // Safe: whitelist + private IP block before curl
    }

    /**
     * SAFE: Using DNS resolution check and strict protocol whitelist.
     */
    public function safeWebhook() {
        $endpoint = $_POST['api_endpoint'] ?? '';
        $parsed = parse_url($endpoint);

        if (!$parsed || ($parsed['scheme'] ?? '') !== 'https') {
            echo json_encode(['error' => 'Only HTTPS endpoints allowed']);
            return;
        }

        $ip = @gethostbyname($parsed['host'] ?? '');
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            echo json_encode(['error' => 'Cannot resolve to public IP']);
            return;
        }

        $data = file_get_contents($endpoint);
        echo json_encode(['response' => $data]);
        // Safe: HTTPS-only + private/reserved IP check
    }
}

// --- Routing ---
if (php_sapi_name() !== 'cli') {
    $logger = new class {
        public function warning($msg) { error_log("[SSRF] " . $msg); }
    };
    $controller = new ProxyController($logger);

    $action = $_GET['action'] ?? 'fetchUrl';
    if (method_exists($controller, $action)) {
        $controller->$action();
    }
}
