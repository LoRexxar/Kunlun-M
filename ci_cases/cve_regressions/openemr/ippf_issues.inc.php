<?php
// Repro: OpenEMR CVE-2026-126489 (GHSA-8j6v-q545-q9q7) second-order SQLi.
// layout_options.field_id is admin-written (interface/super/edit_layout.php),
// read back via sqlFetchArray and spliced into a REPLACE ... SET
// column-name position where add_escape_custom is ineffective.
// Fix 86: openemr framework source (sqlFetchArray/sqlQuery/sqlGetAssoc)
// + sqlStatement CVI-1006 sink.

function issue_ippf_con_save($issue): void
{
    $sets = "id = '" . add_escape_custom($issue) . "'";
    $fres = sqlStatement("SELECT * FROM layout_options " .
        "WHERE form_id = 'CON' AND uor > 0 AND field_id != '' AND edit_options != 'H' " .
        "ORDER BY group_id, seq");
    while ($frow = sqlFetchArray($fres)) {
        $field_id  = $frow['field_id'];
        $value = get_layout_form_value($frow);
        // vulnerable: escaped VALUE-position escape reused on column name
        $sets .= ", " . add_escape_custom($field_id) . " = '" . add_escape_custom($value) . "'";
    }
    sqlStatement("REPLACE INTO lists_ippf_con SET $sets");
}

// Safe contrast: constant SQL (no DB-read interpolation) must NOT fire.
function issue_ippf_con_save_safe(): void
{
    $fres = sqlStatement("SELECT id FROM layout_options WHERE form_id = 'CON'");
    $n = 0;
    while ($frow = sqlFetchArray($fres)) {
        $n++;
    }
    sqlStatement("REPLACE INTO lists_ippf_con SET id = '0', counter = '1'");
}
