<?php
/**
 * CVE-2026-126451 repro (faithful trim) — OpenEMR < 8.5.0 stored XSS
 * via DocumentTemplateRender iframe src.
 *
 * Chain (second order):
 *   portal patient POST JSON body {"templateData": "[{\"name\":\"encounterForm\",\"value\":\"javascript:...\"}]"}
 *   -> Create()/Update(): json_decode(RequestUtil::GetBody())
 *      -> $onsitedocument->TemplateData = SafeGetVal($json, 'templateData')  (stored via ORM Save)
 *   -> staff Read(): $onsitedocument = $this->Phreezer->Get('OnsiteDocument', $pk)  (DB read-back)
 *      -> doRender(null, $onsitedocument->FullDocument, $onsitedocument->TemplateData)
 *   -> DocumentTemplateRender::doRender(): json_decode($json_data) -> $formData[$e['name']] = $e['value']
 *   -> doSubs(): $src = $formData['encounterForm'] ?? ''
 *      -> "<iframe ... src='" . attr($src) . "'></iframe>"   <-- attr() does NOT neutralize javascript: URLs
 * Upstream sink: src/Services/DocumentTemplates/DocumentTemplateRender.php:185/195/232 (v8_4_1)
 */
class RequestUtil
{
    public static function GetBody()
    {
        return file_get_contents('php://input');
    }
}

class OnsiteDocument
{
    public $TemplateData;
    public $FullDocument;

    public function Save()
    {
    }
}

class OnsiteDocumentController
{
    private $Phreezer;

    public function __construct($phreezer)
    {
        $this->Phreezer = $phreezer;
    }

    public function SafeGetVal($json, $name, $default = null)
    {
        return $json->$name ?? $default;
    }

    // store-side: portal patient submits templateData (tainted, persisted)
    public function Create()
    {
        $json = json_decode(RequestUtil::GetBody());
        $onsitedocument = new OnsiteDocument();
        $onsitedocument->TemplateData = $this->SafeGetVal($json, 'templateData', null);
        $onsitedocument->Save();
    }

    // render-side: staff opens the document, ORM reads the stored row back
    public function Read()
    {
        $pk = $_GET['id'];
        $onsitedocument = $this->Phreezer->Get('OnsiteDocument', $pk);
        $templateRender = new DocumentTemplateRender(1, 'admin', 1);
        $prepared_doc = $templateRender->doRender(null, $onsitedocument->FullDocument, $onsitedocument->TemplateData);
        echo $prepared_doc;
    }
}
