<?php
/**
 * Real-world XXE (XML External Entity) injection test file for Kunlun-M scanner.
 * Simulates an XML import/parse service and SOAP-like API endpoint.
 */

class XmlImportController {

    /**
     * VULN: XXE via simplexml_load_string with user-controlled XML body.
     * Attacker can inject: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
     */
    public function importXmlData() {
        $rawXml = file_get_contents('php://input');
        if (empty($rawXml)) {
            echo json_encode(['error' => 'No XML data provided']);
            return;
        }

        libxml_disable_entity_loader(false); // Ensure entity loading is enabled (older PHP default)

        $xml = @simplexml_load_string($rawXml);
        if ($xml === false) {
            echo json_encode(['error' => 'Invalid XML']);
            return;
        }

        $result = [
            'records' => [],
        ];
        foreach ($xml->record as $record) {
            $result['records'][] = [
                'id'   => (string)$record->id,
                'name' => (string)$record->name,
                'data' => (string)$record->data,
            ];
        }

        echo json_encode(['imported' => count($result['records']), 'data' => $result]);
        // Taint source: php://input (user body) -> Sink: simplexml_load_string() without LIBXML_NOENT protection
    }

    /**
     * VULN: XXE via simplexml_load_file with user-controlled file path.
     */
    public function loadXmlFile() {
        $filePath = $_GET['xml_file'] ?? '';
        if (empty($filePath)) {
            echo json_encode(['error' => 'Missing xml_file parameter']);
            return;
        }

        $xml = @simplexml_load_file($filePath);
        if ($xml === false) {
            echo json_encode(['error' => 'Failed to parse XML file']);
            return;
        }

        $config = [];
        foreach ($xml->setting as $setting) {
            $config[(string)$setting['name']] = (string)$setting;
        }

        echo json_encode(['config' => $config]);
        // Taint source: $_GET['xml_file'] -> Sink: simplexml_load_file()
    }

    /**
     * VULN: XXE via DOMDocument::loadXML with user XML data.
     */
    public function parseDomXml() {
        $xmlData = $_POST['xml_data'] ?? '';
        if (empty($xmlData)) {
            echo json_encode(['error' => 'No XML data']);
            return;
        }

        $dom = new DOMDocument();
        // Using default options - no LIBXML_NOENT flag means entities are NOT substituted
        // but without LIBXML_NONET, external entity loading is allowed
        $success = $dom->loadXML($xmlData);
        if (!$success) {
            echo json_encode(['error' => 'Failed to parse XML']);
            return;
        }

        $items = $dom->getElementsByTagName('item');
        $result = [];
        foreach ($items as $item) {
            $result[] = $item->nodeValue;
        }

        echo json_encode(['items' => $result]);
        // Taint source: $_POST['xml_data'] -> Sink: DOMDocument::loadXML() without flags
    }

    /**
     * SAFE: Using LIBXML_NOENT + LIBXML_NONET flags to prevent XXE.
     */
    public function safeImportXml() {
        $rawXml = file_get_contents('php://input');
        if (empty($rawXml)) {
            echo json_encode(['error' => 'No XML data provided']);
            return;
        }

        // Disable external entity loading entirely
        $previous = libxml_disable_entity_loader(true);
        libxml_use_internal_errors(true);

        $xml = @simplexml_load_string($rawXml, 'SimpleXMLElement', LIBXML_NOENT | LIBXML_NONET);
        if ($xml === false) {
            libxml_disable_entity_loader($previous);
            echo json_encode(['error' => 'Invalid XML']);
            return;
        }

        $result = [];
        foreach ($xml->record as $record) {
            $result[] = [
                'id'   => (string)$record->id,
                'name' => (string)$record->name,
            ];
        }

        libxml_disable_entity_loader($previous);
        echo json_encode(['imported' => count($result)]);
        // Safe: entity loader disabled + LIBXML_NONET prevents network access
    }

    /**
     * SAFE: DOMDocument with LIBXML_NONET to block external entities.
     */
    public function safeDomParse() {
        $xmlData = $_POST['xml_data'] ?? '';
        if (empty($xmlData)) {
            echo json_encode(['error' => 'No XML data']);
            return;
        }

        libxml_use_internal_errors(true);
        $dom = new DOMDocument();
        $success = $dom->loadXML($xmlData, LIBXML_NONET | LIBXML_NOENT);
        if (!$success) {
            echo json_encode(['error' => 'Invalid XML']);
            return;
        }

        $result = [];
        foreach ($dom->getElementsByTagName('item') as $item) {
            $result[] = $item->nodeValue;
        }

        echo json_encode(['items' => $result]);
        // Safe: LIBXML_NONET blocks external network entity access
    }
}

// --- Routing ---
if (php_sapi_name() !== 'cli') {
    $controller = new XmlImportController();
    $action = $_GET['action'] ?? 'importXmlData';
    if (method_exists($controller, $action)) {
        $controller->$action();
    }
}
