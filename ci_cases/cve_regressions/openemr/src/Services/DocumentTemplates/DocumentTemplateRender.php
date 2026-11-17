<?php
/**
 * CVE-2026-126451 repro (faithful trim) — sink side.
 * Upstream: openemr v8_4_1 src/Services/DocumentTemplates/DocumentTemplateRender.php
 * doRender() lines 105-109 (json_decode -> formData) and doSubs() lines 183-185/230-232
 * (iframe src='...' concat). attr() is htmlspecialchars-based: it escapes quotes but
 * does NOT neutralize a javascript: URL scheme, so the iframe src sink stays live.
 */
function attr($s)
{
    return htmlspecialchars((string) $s, ENT_QUOTES);
}

class DocumentTemplateRender
{
    private $pid;
    private $user;
    private $encounter;

    public function __construct($pid, $user, $encounter)
    {
        $this->pid = $pid;
        $this->user = $user;
        $this->encounter = $encounter;
    }

    public function doRender($template_id, $template_content = null, $json_data = null): string
    {
        $formData = [];
        if ($json_data) {
            // upstream doRender(): format [{"name":"","value":"","type":""}]
            $jsData = json_decode((string) $json_data, true);
            foreach ($jsData as $e) {
                $formData[$e['name']] = $e['value'] ?? '';
            }
        }
        $template = $template_content ?? $this->fetchTemplateDocument($template_id)['template_content'];
        $edata = $this->doSubs($template, $formData);
        return $edata;
    }

    private function fetchTemplateDocument($id)
    {
        return ['template_content' => '{EncounterForm:fee_sheet}'];
    }

    private function doSubs($s, $formData): mixed
    {
        if (preg_match('/^\{(EncounterForm):(\w+)\}/', (string) $s, $matches)) {
            $formname = $matches[2];
            $src = $formData['encounterForm'] ?? '';
            $sigfld = "<script>page.isFrameForm=1;page.encounterFormName=" . $formname . "</script>";
            // upstream line 232 — the sink
            $sigfld .= "<iframe id='encounterForm' class='lbfFrame' style='height:100vh;width:100%;border:0;' src='" . attr($src) . "'></iframe>";
            $s = $sigfld;
        }
        return $s;
    }
}
