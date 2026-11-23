<?php
// Repro caller: OpenEMR CVE-2026-126491 — patient_select.php (findBy=Any)
// is the trigger call-site for getByPatientDemographics(). Without a caller
// the uncalled function is dead-code-gated.
require_once '../../globals.php';
require_once $srcdir . '/patient.inc.php';

$findBy = $_REQUEST['findBy'] ?? '';
$patient = $_REQUEST['patient'] ?? '';
$given = "pid, id, lname, fname";
$orderby = "lname ASC, fname ASC";
$sqllimit = "all";
$fstart = "0";

$rets = array(
    "Any" => getByPatientDemographics($patient, $given, $orderby, $sqllimit, $fstart),
);
