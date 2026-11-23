<?php
// Repro caller: OpenEMR CVE-2026-126489 — add_edit_issue.php entry.
// $issue is the id of the just-saved row (server-side, untainted); the
// vulnerability rides the second-order sqlFetchArray path, not $issue.
require_once '../../globals.php';
require_once $srcdir . '/ippf_issues.inc.php';

if (!empty($_POST['form_save'])) {
    $issue = strval($savedRecord['id'] ?? '0');
    $text_type = $_POST['type'] ?? '';
    if ($text_type == 'contraceptive') {
        issue_ippf_con_save($issue);
    }
    if ($text_type == 'ippf_gcac') {
        issue_ippf_gcac_save($issue);
    }
}
