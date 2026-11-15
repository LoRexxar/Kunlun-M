<?php
// Repro: OpenEMR CVE-2026-126491 (GHSA-pc2q-9pcw-v899) — incomplete fix of
// CVE-2026-33910. getByPatientDemographics() (library/patient.inc.php ~L668)
// reads layout_options.field_id via sqlFetchArray and splices it through
// add_escape_custom() into the patient-search WHERE column-name position,
// then executes via sqlStatement. The sibling getByPatientDemographicsFilter()
// got escape_sql_column_name() in 8.0.0.3; this function was missed until
// 8.5.0. Plant primitive: interface/super/edit_layout.php (Layout Editor).
// Fix 86 chain: openemr framework source (sqlFetchArray) + sqlStatement sink.

function getByPatientDemographics(
    $searchTerm = "%",
    $given = "pid, id, lname, fname",
    $orderby = "lname ASC, fname ASC",
    $limit = "all",
    $start = "0"
) {
    $layoutCols = sqlStatement(
        "SELECT field_id FROM layout_options WHERE form_id = 'DEM' AND field_id not like ? AND uor != 0",
        ['em\_%']
    );

    $sqlBindArray = [];
    $where = "";
    for ($iter = 0; $row = sqlFetchArray($layoutCols); $iter++) {
        if ($iter > 0) {
            $where .= " or ";
        }
        // Column-name position: add_escape_custom() (mysqli_real_escape_string)
        // is useless for identifiers — the original "1 OR 1=1" PoC injects here.
        $where .= " " . add_escape_custom($row["field_id"]) . " like ? ";
        array_push($sqlBindArray, "%" . $searchTerm . "%");
    }

    $sql = "SELECT $given FROM patient_data WHERE $where ORDER BY $orderby";
    $rez = sqlStatement($sql, $sqlBindArray);
    $returnval = [];
    for ($iter = 0; $row2 = sqlFetchArray($rez); $iter++) {
        $returnval[$iter] = $row2;
    }
    return $returnval;
}

// Safe contrast: same loop shape, but the executed SQL is constant (no
// DB-read interpolation) — must NOT fire.
function getByPatientDemographics_safe()
{
    $layoutCols = sqlStatement("SELECT field_id FROM layout_options WHERE form_id = 'DEM'");
    $n = 0;
    for ($iter = 0; $row = sqlFetchArray($layoutCols); $iter++) {
        $n++;
    }
    sqlStatement("SELECT pid, lname FROM patient_data WHERE lname like ? ORDER BY lname", ['%a%']);
    return $n;
}
