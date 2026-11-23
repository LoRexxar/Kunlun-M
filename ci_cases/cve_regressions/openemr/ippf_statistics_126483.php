<?php
// Repro: OpenEMR CVE-2026-126483 (GHSA-p2ch-6856-w69j) —
// interface/reports/ippf_statistics.php form_facility SQLi (v8.4.1:
// L46 source $_POST['form_facility'], L1455 interpolation into $query
// via .= append, L1460 sqlStatement sink; fixed in 8.5.0 by ? binding).
//
// Fix 103: AUG_ASSIGN (.=) LHS is read+write — the $query value assembled
// across several .= appends (one carrying the tainted interpolation) must
// flow forward to the sqlStatement sink.  Previously the .= chain broke
// taint: 0 detections on the whole file.
// Fix 104: `$patient_id = $row0['pid']` with $row0 derived via dfg from
// sqlFetchArray(sqlStatement(...)) made the negated hadRecentAbService()
// predicate a "whitelist guard on $query" (wrong-direction dataflow,
// name-based), killing every sqlStatement chain in the file.
require_once "../globals.php";

$from_date = $_POST['form_from_date'] ?? '0000-00-00';
$to_date = $_POST['form_to_date'] ?? date('Y-m-d');
$form_facility = $_POST['form_facility'] ?? '';

$sqlBindArray = [];
$query = "SELECT fe.pid FROM form_encounter AS fe " .
    "WHERE fe.date >= ? AND fe.date <= ? ";
array_push($sqlBindArray, $from_date . ' 00:00:00', $to_date . ' 23:59:59');

if ($form_facility) {
    // vulnerable: interpolated instead of ? bound (8.5.0 fix)
    $query .= "AND fe.facility_id = '$form_facility' ";
}
$query .= "ORDER BY fe.pid";

// Fix 104 scenario: guard var is a DB-read derivative of the SAME
// $query (res0 loop) — with the pre-Fix-104 wrong-direction acceptance
// this negated predicate became a "whitelist guard on $query" and
// disqualified the sqlStatement sink below (exact ippf_statistics.php
// shape: main loop $row = sqlFetchArray(sqlStatement($query)), then
// !hadRecentAbService($row['pid']) before later $query sinks).
$res0 = sqlStatement($query, $sqlBindArray);
$row0 = sqlFetchArray($res0);
$patient_id = $row0['pid'];
if (!hadRecentAbService($patient_id)) {
    exit; // fall-through reporting path would continue here
}

// sink: superglobal → .= interpolation (Fix 103 chain), must survive
// the Fix 104 guard shape above
$res = sqlStatement($query, $sqlBindArray);
$row = sqlFetchArray($res);

function hadRecentAbService($pid)
{
    return false;
}
