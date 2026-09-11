<?php
/**
 * Real-world Variable Injection test file for Kunlun-M scanner.
 * Simulates a configuration handler and form processor using extract/parse_str.
 */

class ConfigController {

    /**
     * VULN: Variable injection via extract() with $_GET parameters.
     * Attacker can overwrite internal variables like $db_host, $admin, etc.
     */
    public function loadConfig() {
        // Internal defaults
        $db_host = 'localhost';
        $db_user = 'app_user';
        $db_pass = 'secret_password';
        $debug   = false;
        $admin   = false;

        // VULN: extract() pulls user-controlled keys into local scope
        extract($_GET, EXTR_OVERWRITE);

        // Attacker can set ?admin=1&debug=1&db_host=attacker.com&db_pass=hacked
        echo json_encode([
            'db_host' => $db_host,
            'db_user' => $db_user,
            'debug'   => $debug,
            'admin'   => $admin,
        ]);
        // Taint source: $_GET -> Sink: extract() with EXTR_OVERWRITE
    }

    /**
     * VULN: Variable injection via parse_str() with $_POST data.
     * Attacker can inject arbitrary variables.
     */
    public function processForm() {
        $formData = $_POST['form_data'] ?? '';
        if (empty($formData)) {
            echo json_encode(['error' => 'No form data']);
            return;
        }

        $internalFlag = false;
        $maxRecords   = 100;
        $allowedTable = 'users';

        // VULN: parse_str() creates local variables from user input
        parse_str($formData);

        // Attacker can inject: form_data=internalFlag=1&maxRecords=999999&allowedTable=admins
        echo json_encode([
            'flag'      => $internalFlag,
            'max'       => $maxRecords,
            'table'     => $allowedTable,
        ]);
        // Taint source: $_POST['form_data'] -> Sink: parse_str()
    }

    /**
     * VULN: Variable injection via extract() on $_REQUEST with EXTR_SKIP,
     * but still dangerous as it adds new variables that may be used later.
     */
    public function applySettings() {
        $settings = [];

        $theme     = 'default';
        $language  = 'en';
        $page_size = 20;

        // EXTR_SKIP won't overwrite, but will ADD new variables from user input
        extract($_REQUEST, EXTR_SKIP);

        // Attacker can inject new variables not predefined:
        // ?is_admin=1&config_path=/tmp/evil
        if (isset($is_admin) && $is_admin === '1') {
            // This variable was injected by the user!
            $settings['admin'] = true;
        }

        if (isset($config_path)) {
            // Attacker-controlled config path
            $settings['config'] = $config_path;
        }

        $settings['theme']    = $theme;
        $settings['language'] = $language;
        $settings['pageSize'] = $page_size;

        echo json_encode($settings);
        // Taint source: $_REQUEST -> Sink: extract() EXTR_SKIP (adds new variables)
    }

    /**
     * SAFE: Don't use extract() on user data. Manually assign whitelisted keys.
     */
    public function safeLoadConfig() {
        // Internal defaults
        $config = [
            'db_host' => 'localhost',
            'db_user' => 'app_user',
            'db_pass' => 'secret_password',
            'debug'   => false,
            'admin'   => false,
        ];

        // Only allow specific keys to be overridden
        $allowedKeys = ['db_host', 'debug'];
        foreach ($allowedKeys as $key) {
            if (isset($_GET[$key])) {
                // Validate each allowed key
                if ($key === 'db_host') {
                    $value = $_GET[$key];
                    if (preg_match('/^[a-zA-Z0-9\.\-]+$/', $value)) {
                        $config[$key] = $value;
                    }
                } elseif ($key === 'debug') {
                    $config[$key] = (bool)$_GET[$key];
                }
            }
        }

        echo json_encode($config);
        // Safe: manual assignment with whitelist + per-key validation
    }

    /**
     * SAFE: parse_str() into an array (second parameter) instead of local scope.
     */
    public function safeProcessForm() {
        $formData = $_POST['form_data'] ?? '';
        if (empty($formData)) {
            echo json_encode(['error' => 'No form data']);
            return;
        }

        // Safe: parse into an array instead of local variables
        $params = [];
        parse_str($formData, $params);

        // Whitelist allowed keys
        $allowedKeys = ['search', 'page', 'sort', 'filter', 'limit'];
        $safeParams = [];
        foreach ($allowedKeys as $key) {
            if (isset($params[$key])) {
                $safeParams[$key] = $params[$key];
            }
        }

        // Validate types
        $safeParams['page']  = max(1, (int)($safeParams['page'] ?? 1));
        $safeParams['limit'] = min(100, max(1, (int)($safeParams['limit'] ?? 20)));

        echo json_encode($safeParams);
        // Safe: parse_str into array + whitelist + type validation
    }
}

// --- Routing ---
if (php_sapi_name() !== 'cli') {
    $controller = new ConfigController();
    $action = $_GET['action'] ?? 'loadConfig';
    if (method_exists($controller, $action)) {
        $controller->$action();
    }
}
