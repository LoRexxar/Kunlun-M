<?php
// CVE-2026-126480 mini repro (part 1/2): caller — faithful entry of the
// Zend Ccr module. revandapproveAction() passes the ENTIRE $_REQUEST
// array to CcrTable::insertApprovedData(). No ACL / CSRF (that is the
// reachability side of the CVE); the injection surface is the array KEYS.
// Real code: interface/modules/zend_modules/module/Ccr/src/Ccr/Controller/
//            CcrController.php:246-256 (openemr v8_4_1).
require_once __DIR__ . '/../Model/CcrTable_126480.php';

use Ccr\Model\CcrTable;

// Caller for the uncalled method (dead-code gate needs a cg edge; the real
// entry is the Zend MVC dispatcher, mirrored here as a direct call).
function ccr_revandapprove_dispatch($request)
{
    if ($request->getPost('setval') == 'approve') {
        $table = new CcrTable();
        $table->insertApprovedData($_REQUEST);
        return true;
    }
    return false;
}

ccr_revandapprove_dispatch(null);
