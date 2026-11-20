#!/usr/bin/env python3
"""CVE mini-repro regression gate — structural fix item #3 (2026-11).

Six CVE campaigns kept rediscovering the same engine blind spots because
each fix's minimal repro lived in /tmp and vanished. This gate freezes
those repros under ci_cases/cve_regressions/ with their EXPECTED findings
and asserts them after every engine change — an accident becomes an
invariant.

Usage (from the Kunlun-M repo root, venv active):
    python3 ci_cases/run_cve_regressions.py

Each case declares: file → expected (rule, count) pairs. A scan of the
whole cve_regressions dir runs once; results are read back from the DB by
scan_task_id (CLI tail tables are cumulative and unusable for this).

Adding a case: copy the minimized repro here, scan once manually, record
the expected rows below, commit both. NEVER weaken an expectation to make
a failing engine pass — investigate instead.
"""
import os
import glob
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CASES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cve_regressions')

# file basename → {cvi_id: min_count}
EXPECTATIONS = {
    # Fix 55: top-level (file-scope) calls must produce cg edges so the
    # callee escapes the dead-code gate. Was 0 rows before Fix 55.
    'CVE-2026-121429_top_level_cg.php': {'1011': 1},
    # Fix 67: symfony 1.x form proxy — $form->bind($request->getParameter(...))
    # taints the form object; $form['x']->getValue() reads are sources.
    'CVE-2020-7246_sf1_form_unlink.php': {'1017': 1},
    # Fix 68: Java deserialization chain — request.getInputStream() → new
    # ObjectInputStream(...) → readObject(); and IIOP SkeletonStrategy
    # .readParams before auth (CVE-2026-15564, WildFly EjbCorbaServant).
    'CVE-2026-15564_iiop_readparams.java': {'6035': 1},
    # Fix 69: WP posts_where filter SQLi — $_REQUEST → WP_Query param →
    # $wp_query->get() source → $wpdb->esc_like() concat (CVE-2026-114189).
    'CVE-2026-114189_wp_posts_where.php': {'1006': 1},
    # Fix 70: sprintf SQL-literal-concat sentinel — craft.search term value
    # interpolated unescaped into '%s' (CVE-2026-115934 Craft CMS).
    'CVE-2026-115934_craft_sprintf_sql.php': {'1006': 1},
    # Fix 71: PDO generic DB layer — $_GET['id'] interpolated into
    # $dbh->query("... id=$id") (CVE-2026-93997 SourceCodester Drug
    # Recommendation System /Admin/edit_symptom.php). Safe contrast in the
    # same file (prepare+bound execute) must NOT fire.
    'CVE-2026-93997_pdo_query_sqli.php': {'1005': 1},
    # CVE-2026-36236 (SourceCodester Engineers Online Portal v1.0,
    # update_password.php): $_POST['new_password'] interpolated into a
    # double-quoted mysqli_query UPDATE — native superglobal→interp→sink
    # chain, no engine fix needed; regression guard for the native path.
    # Safe contrast (mysqli_prepare+bind) must NOT fire.
    'CVE-2026-36236_post_interp_sqli.php': {'1006': 1},
    # Fix 84 (CVE-2026-30530 SourceCodester Online Food Ordering System):
    # foreach($_POST) → $data column list → $this->query(INSERT/UPDATE) —
    # a METHOD-BODY generic-DB call on a SQLite3 subclass.  Fix 71e's
    # file-scope-only probe gate missed every in-function call; now the
    # probe binds when the args' bounded backward dfg walk reaches a
    # superglobal inside the function.  Entry-param wrapper contrast
    # (run_raw_sql84) must NOT fire.
    'CVE-2026-30530_sqlite3_method_sqli.php': {'1005': 1},
    # Fix 73: PHP include/require language-construct sinks (SuiteCRM,
    # CVE-2026-71550) — $_REQUEST['aow_action'] concat → require_once
    # dynamic file inclusion.  Both the custom/ and modules/ branches.
    'CVE-2026-71550_aow_require_once.php': {'1007': 2},
    # Fix 120 + CVE-2026-111215 (Netgate pfSense CE <=2.9.0 wireless parent
    # iface command injection): $_POST['if'] → $clone array write-back →
    # param → interface_get_wireless_base passthrough → {$baseif} interp →
    # exec.  The .inc library file also regression-guards Fix 120 (.inc
    # discovery: php set + PHP-open-tag content sniff).
    'CVE-2026-111215_interfaces.inc': {'1011': 1},
    # Fix 123/124/125 (CVE-2026-111217 pfSense CARP VHID command injection,
    # CVSS 8.6): $_POST[vhid] → saveVIP → config_set_path("virtualip/vip/0")
    # → config_get_path('virtualip/vip') → get_configured_vip_detail →
    # get_configured_vip → {$vhid} interp → exec.  Regression-guards the
    # config store→load bridge (Fix 123), corpus-wide return-value DFG
    # propagation (Fix 124a/b/c), the summary graph-evidence override
    # (Fix 125/125b: a safe/literal callee summary must not kill taint
    # entering the call op through bridge/binding dfg edges) and the
    # source-summary precedence over caller deps (Fix 125c).
    'CVE-2026-111217_carp_vhid_configbridge.php': {'1011': 1},
    # CVE-2026-111214 (pfSense SA-26_23, CVSS 8.6): QinQ parent-interface
    # command injection. $_POST['if'] stored unvalidated into the QinQ entry
    # (edit:136), surfaced as vlanif via vlan_interface(), interpolated into
    # ifconfig exec() directly at member-edit time (edit:212, 'via
    # subscript') and after config store->load on the delete path
    # (interfaces_qinq.php:70, 'via member chain'). Native detection on the
    # Fix 123/124 config bridge — zero engine change; task6720 rows
    # 16707/16708 are the full-corpus evidence.
    'CVE-2026-111214_qinq_parent_if.php': {'1011': 2},
    # Fix 72: config-file source chain (Siemens meta-iot2050,
    # CVE-2026-109830) — json.load → getConfig summary → getter summary →
    # subprocess.call("... " + initMode, shell=True). Safe contrast
    # (argument-list reboot, no config input) must NOT fire.
    'board-bootup-conf.py': {'7000': 1},
    # Engine array-writeback fix (getSuggestion array item write-back):
    # taint must survive through array store → return → consumer.
    'CVE-2026-62007_array_writeback.php': {'1000': 1},
    # Fix 59: Slim route closures are framework dispatch entries (ast
    # in-edge), NOT dead code; $request->getQueryParams() is a source.
    # Blind before Fix 59 (dead-code gate + no slim framework config).
    'Fix59_slim_route_closure.php': {'1011': 1},
    # Fix 74: a repair verdict on ONE concat operand must not kill the
    # whole trace — dirname(__DIR__,2) judged repair, sprintf($iso) side
    # never visited.  $_SERVER['HTTP_ACCEPT_LANGUAGE'] → sprintf →
    # require (CVE-2026-41228, froxlor 2.3.5 Language.php RFI).
    'CVE-2026-41228_lang_accept_require.php': {'1007': 1},
    # Fix 75/76/76b/77 chain: php://input literal source → ApiParameter
    # ctor $this->prop store → getParam read bridge → new-site ctor arg →
    # file_put_contents path-literal-.php content traced (CVE-2026-41229,
    # froxlor API writes lib/userdata.inc.php).  3-file repro in
    # php-generic/ (helpers renamed to avoid bare-callee hijack).
    'CVE-2026-41229_froxlor_mysqlserver.php': {'1017': 1},
    # Fix 78 chain (CVE-2026-41478 Saltcorn sync.js): req.body →
    # ObjectPattern destructure → closure capture → for-of
    # ArrayPattern over Object.entries → helper call arg → param →
    # template literal → db.query.  Three GT sinks (L53/L80/L173).
    'sync.js': {'3104': 3},
    # Fix 79 (CVE-2026-32613 Spinnaker echo SpEL RCE): user-authored
    # pipeline expectedArtifacts (TYPE-qualified source
    # Pipeline.getExpectedArtifacts) → null-check weak re-assign →
    # enhanced-for loop var → ExpressionTransform.transformMap →
    # parser.parseExpression under unrestricted StandardEvaluationContext.
    'ExpressionTransform.java': {'6012': 1},
    # Fix 133 (CVE-2026-123551 OpenAM Liberty ID-FF unvalidated forward):
    # request.getParameter("RelayState") → lrURL → FSUtils.forwardRequest →
    # same-container check → newUrl.substring(index) receiver flow →
    # request.getRequestDispatcher(resource) internal forward that skips
    # REQUEST-only security filters. Three-part fix: 133a String.* typed
    # receiver passthrough + typed-lookup-before-fullname ordering,
    # 133b reaching-def receiver edge (was first-match decl node = dead end),
    # 133c file-scoped declared-type fallback index (use nodes carry no
    # java_type), 133d immutable-receiver guard on fluent back-flow (String
    # substring back-edge poisoned every later read of the receiver).
    # 6006: new URL(newUrl) SSRF arm; 6015: sendRedirect + forward sinks.
    'FSUtils.java': {'6006': 1, '6015': 2},
    # Fix 85 (CVE-2026-44566 Open WebUI): FastAPI UploadFile type-hint
    # param is a framework source; file.filename → f-string template →
    # open(file_path, "wb+") arbitrary file write. Subdir python/ carries
    # its own requirements.txt so detect_framework resolves fastapi (not
    # the repo-root django one).
    'CVE-2026-44566_fastapi_upload.py': {'7005': 1},
    # Fix 118 (CVE-2026-42048 langflow <=1.8.4, GHSA-9whx-c884-c68q):
    # FastAPI Pydantic body-model route param is a framework source —
    # request.kb_names → pathlib truediv (kb_user_path / kb_name) →
    # KBStorageHelper.delete_storage(kb_path) → shutil.rmtree(kb_path)
    # arbitrary directory delete.  Depends alias current_user stays clean.
    'CVE-2026-42048_langflow_kb_bulk_delete.py': {'7005': 1},
    # Fix 117a/b/c/e/f/g/m (CVE-2026-110279 IBM ContextForge MCP Gateway):
    # request.headers → {k.lower(): v for k,v in headers.items()} dict-comp
    # → passthrough_headers["Authorization"]=v subscript write-back → await
    # invoke_tool → httpx.AsyncClient(headers=...) outbound credential
    # override.  Engine chain: comprehension+receiver-passthrough summaries,
    # subscript write-back DFG, await flow, CVI_7016 sink.
    'CVE-2026-110279_mcp_passthrough_headers.py': {'7016': 1},
    # Fix 134 (CVE-2026-64849 MLflow <3.15.0, GHSA-7gwp-5pfp-969j): stored
    # second-order webhook SSRF.  store.get_webhook row read is a source
    # (mlflow app overlay, Fix 114a doctrine); webhook.url flows through
    # params to session.post(...) whose receiver type comes from BOTH the
    # annotated param (requests.Session) and the constructor reaching-def
    # (requests.Session()) — typed-receiver sink 'requests.Session.post'
    # (CVI_7004); raise-only _validate_webhook_url must not sanitize.
    'CVE-2026-64849_mlflow_webhook_ssrf.py': {'7004': 1},
    # Fix 91 (CVE-2026-33078 roxy-wi <8.2.6.4): Flask route path params
    # are HTTP sources — @bp.route('/section/haproxy/<server_ip>/save')
    # binds URL vars to view params with no request.* anywhere; the param
    # flows into '%s'-formatted SQL at cursor.execute().  Subdir flask/
    # carries its own requirements.txt so detect_framework resolves flask.
    # Fix 92 safe contrasts in the same file (route-tainted args into
    # UNRESOLVED peewee-style ORM builders .select().where().execute())
    # must NOT fire.
    'CVE-2026-33078_flask_path_sqli.py': {'7002': 1},
    # Fix 93c/94/96a-e/99 (CVE-2026-29080 rucio <=35.8.4 FilterEngine
    # SQLi): Flask route → request.args.get('filters') → ast.literal_eval
    # → FilterEngine.__init__ (constructor arg binding) → for-loop tuple
    # target → list .append write-back → self._filters cross-method read →
    # str.format(all-args passthrough) → sqlalchemy text() interpolation.
    # Every hop of this chain was a silent taint island before the fixes.
    'CVE-2026-29080_rucio_filter_engine_sqli.py': {'7002': 1},
    # Fix 86 (CVE-2026-126489 OpenEMR second-order SQLi): admin-written
    # layout_options.field_id read back via sqlFetchArray (openemr
    # framework source) → spliced into REPLACE ... SET column-name
    # position → sqlStatement sink. Caller file matters: without it the
    # uncalled function is dead-code-gated. Safe contrast (constant SQL)
    # in the same file must NOT fire.
    'ippf_issues.inc.php': {'1006': 1},
    # Fix 103/104 (CVE-2026-126483 OpenEMR ippf_statistics.php SQLi):
    # $_POST['form_facility'] interpolated into $query assembled via
    # AUG_ASSIGN (.=) appends → sqlStatement (3 executions of the tainted
    # $query).  Fix 103: .= LHS is read+write — pre-fix the append chain
    # broke taint (0 detections).  Fix 104: the negated
    # hadRecentAbService($row0['pid']) guard with $row0 from
    # sqlFetchArray(sqlStatement($query)) sits BEFORE the sinks — the old
    # wrong-direction whitelist-guard acceptance killed every chain.
    'ippf_statistics_126483.php': {'1006': 3},
    # Fix 106 (CVE-2026-126482 OpenEMR ERA upload chain): uploaded-file
    # tmp_name → rename() to web-accessible path (1017 file-write primitive
    # at era_payments.php:158), and the ERA file content → preg_split →
    # $pid interpolated into sqlQuery (1006 SQLi at SLEOB.php:39 — the CVE
    # core sink; parseERA string-const callback dispatch reaches the body).
    # Frozen from task 6282 (subdir scan, framework marker resolves; root
    # mixed-dir scan under-detects SLEOB — the documented subdir trap).
    'era_payments.php': {'1017': 1},
    'SLEOB.php': {'1006': 1},
    # Fix 111/112/113 (CVE-2026-126480 OpenEMR Ccr parameter-name SQLi):
    # the whole $_REQUEST is passed to CcrTable::insertApprovedData() and
    # the taint surface is the ARRAY KEYS ('patient_data<col>-sel' →
    # substr → .= concat → UPDATE ... SET column list).  QueryUtils
    # ::sqlStatementThrowException registered as a query-text sink (Fix
    # 111, arg0-only); framework Class::method sink patterns tail-match
    # fully-qualified static call sites (Fix 112 — \OpenEMR\...\QueryUtils
    # ::method); wrapper delegation bodies inside the SQL wrapper family
    # are demoted to unconfirmed (Fix 113 — sql.inc.php:99/124 double
    # rows whose callers are themselves registered sink lines).
    'CcrTable_126480.php': {'1006': 1},
    # Fix 89 (CVE-2026-126491 OpenEMR patient_select match-arm SQLi):
    # the ONLY call-site of getByPatientDemographics() lives inside a
    # PHP 8 match arm — MatchArm/MatchDefaultArm are in no _*_NODES set
    # and phply nodes have no children(), so arm bodies (and every call
    # in them) were invisible: no call node → no cg edge → dead-code gate
    # killed the chain. sqlFetchArray (openemr source) → $row['field_id']
    # → $where → $sql → sqlStatement sink. Safe contrast in the same file
    # must NOT fire.
    'patient.inc.php': {'1006': 1},
    # Fix 114 (CVE-2026-126451 OpenEMR stored XSS via DocumentTemplateRender
    # iframe src): second-order chain — portal patient stores JSON into
    # OnsiteDocument.TemplateData (Create()); staff Read() fetches the row
    # back via $this->Phreezer->Get('OnsiteDocument', $pk) (Fix 114a: ORM
    # fetch object registered as a context-gated second-order source) →
    # doRender → json_decode → $formData['encounterForm'] → concat into
    # src='".attr($src)."' — htmlspecialchars (ENT_QUOTES) kills quote
    # breakout but NOT javascript: schemes, so Fix 114b's URL-attribute
    # escape sentinel (Path F + isolated sub-pass) reports CVI-1000 at the
    # concat line.
    'DocumentTemplateRender.php': {'1000': 1},
    # Fix 115 (CVE-2026-126478 OpenEMR Syndromic Surveillance SQLi):
    # form_icd_codes[] POST array (Fix 115a: getPost on a $request receiver
    # = openemr source) imploded into an UNQUOTED numeric IN() clause
    # wrapped in add_escape_custom (no-op for quote-free payloads —
    # deliberately NOT a repair, see rules/tamper/php/openemr.py) on both
    # UNION arms, executed via QueryUtils::fetchRecords (Fix 115c: arg0 =
    # caller-built query text sink).  Fix 115b: the getXyzTable() getter
    # (no declared return type) resolves its property class from the
    # constructor DI hint so the chained call gets a real cg edge.
    # Two arms -> two sink rows (count + rows fetchRecords sites).
    'CVE-2026-126478_syndromic_in_sqli.php': {'1006': 2},
    # Fix 116 (CVE-2026-126481 OpenEMR ERA 835 path traversal): uploaded
    # X12 835 (tmp_name file source) parsed by ParseERA; the registered
    # callback declares `global $eraname;` and writes GS04/ISA13-derived
    # content into it (Fix 116a: normalizer emits one marker per declared
    # name from phply Global.nodes; Fix 116b: DFG capture pass links the
    # function-scope WRITE to FILE-scope uses, PHP process-global
    # semantics); the file scope then interpolates $eraname into the
    # rename()/copy() destination -> arbitrary file write.  Fix 116c
    # (is_string et al. as neutral shape predicates) un-vetoes the
    # `if (is_string($tmp_name) && $tmp_name !== '')` upload guard.
    # Two sinks (rename :73 / copy :77); the island contrast (no `global`)
    # must NOT fire.
    'CVE-2026-126481_global_capture.php': {'1017': 2},
    # Fix 119 (CVE-2026-44381 MISP 2.5.36 CakePHP 2.x order-field SQLi):
    # $this->passedArgs (Fix 119a source) copied verbatim into
    # Model::find('all', $rules) rules['order'] / $this->request['named']
    # ['sort'] concatenated into $params['order'] — both reach
    # DboSource::renderStatement ORDER BY unescaped (fix 53fc6be7da
    # whitelist via findOrder).  Fix 119b: prefix member-chain semantics
    # ($this.request.named.sort under $this.request).  Fix 119c: ->find(
    # ORM-entry sink (framework-gated cakephp/).  DboSource.php row: the
    # extract($data) inside renderStatement carries the tainted order —
    # interior of the same chain (CVI 1014).  Tree under cakephp/ carries
    # the lib/Cake marker for per-subdir framework detection.
    'EventsController.php': {'1006': 1},
    'ShadowAttributesController.php': {'1006': 1},
    'DboSource.php': {'1014': 1},
    # Fix 119g scope-gate positives: the gated property sources must still
    # fire in their class contexts (controller passedArgs / view_helper
    # request.data).
    'ProbeController.php': {'1006': 1},
    'ProbeHelper.php': {'1011': 1},
    # CVE-2026-124469 (OpenEMR <= 8.2.0 Fee Sheet drug-inventory ORDER BY
    # SQLi, CVSS 9.4): $_POST['prod'][N]['warehouse'] → FeeSheet
    # ::checkInventory ($warehouse_id :845) → global sellDrug positional
    # wrapper (interface/drugs/drugs.inc.php, 9th arg) → DrugSalesService
    # ::sellDrug $default_warehouse interpolated into
    # "di.warehouse_id != '...'" ORDER BY → QueryUtils
    # ::sqlStatementThrowException (upstream fix 31e13ee2d9 binds ?).
    # Native detection, zero engine change this battle (Fix86 sink +
    # Fix120 .inc discovery + Fix106/110 chain plumbing).  Frozen from
    # task 6575 row 16862; GT on full focus corpus task 6574 row 16861
    # (DrugSalesService.php:326, all 6 files faithful to v8_2_0).
    'CVE-2026-124469_DrugSalesService.php': {'1006': 1},
    # CVE-2026-124490 (OpenEMR <= 8.2.2 oe-module-faxsms, CVSS 9.4,
    # GHSA-38jw-pwgq-9hpj): RCFaxClient::disposeDocument arbitrary file
    # read/write/delete — $_REQUEST['_ACTION_COMMAND'] → AppDispatch
    # ::dispatch (alias &$this->_request) → getRequest('file_path') →
    # file_put_contents($where)/unlink($where) + sendFile →
    # FaxUploadStaging::decryptFileBytes → file_get_contents.  Native
    # detection, zero engine change.  Plus TWO unpatched sibling vendors
    # found in this battle (GHSA names only RingCentral):
    #  - SignalWireClient::disposeDocument (same write/delete shape) and
    #    sendFax isContent=1 bypass → uploadFileForFax copy() staged
    #    read (PDF-constrained exfil, task 6588 row 16895);
    #  - EtherFaxActions::sendFax guards only under empty($isContent)
    #    → EtherFaxClient::etherFaxSend is_file() branch reads AND
    #    unlinks any existing file (task 6588 rows 16899/16900).
    # Frozen from task 6591 (openemr/ subdir scan, framework marker
    # resolves): GT on full module corpus task 6588 (8 TP family rows
    # 16893/16894/16901/16895/16896/16898/16899/16900; the 20 echo rows
    # there are attr()/js_escape()/text() outputs that die under the
    # Fix 108 openemr framework repair set — proven by marker-root
    # rescan task 6590: 37 → 17 rows, exactly the 20 echo rows gone).
    'CVE-2026-124490_RCFaxClient.php': {'1017': 2, '1000': 1},
    'CVE-2026-124490_SignalWireClient.php': {'1017': 3, '1000': 1},
    'CVE-2026-124490_EtherFaxClient.php': {'1002': 1, '1017': 1},
    'CVE-2026-124490_FaxUploadStaging.php': {'1002': 1},
    'CVE-2026-124490_AppDispatch.php': {'1000': 2},
}

# Fix 119g (CVE-2026-44381): negative expectations — these files MUST stay
# at ZERO findings.  The scope_probe triad is copied verbatim from the
# battle's falsifiable probe: Shell::$params is CLI argv (Console/Command
# context), NOT a web source; before Fix 119g the receiver-blind member
# match turned it into system() command-injection FPs (MISP task 6510
# ServerShell et al.).  A regression here re-opens the whole CLI FP family.
FORBIDDEN = {
    'ProbeShell.php': ('1011', '1002', '1006'),
    # CVE-2026-124490 safe-escape contrast: the real module echoes every
    # request-derived value through OpenEMR's official output helpers
    # (attr/attr_js/js_escape/text — library/htmlspecialchars.inc.php
    # wrappers, Fix 108 openemr framework repair set).  A 1000 row here
    # means the framework-scoped repair set stopped applying (e.g.
    # openemr composer marker lost, or the repair set was broken).
    # Context caveat per Fix 114b: attr() inside URL attributes
    # (src=/href=) is NOT a repair — that shape lives in
    # DocumentTemplateRender.php (sentinel), which must keep firing.
    'CVE-2026-124490_contact_escape.php': ('1000',),
}


def main() -> int:
    # sys.path[0] is the script's dir (ci_cases/), not the repo root —
    # django needs the repo root importable for Kunlun_M.settings.
    if REPO not in sys.path:
        sys.path.insert(0, REPO)
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Kunlun_M.settings')
    import django
    django.setup()
    from web.index.models import ScanTask, ScanResultTask

    def _case_exists(fname: str) -> bool:
        if os.path.exists(os.path.join(CASES_DIR, fname)):
            return True
        # Fix 67: framework-scoped subdirs
        for d in os.listdir(CASES_DIR):
            sub = os.path.join(CASES_DIR, d, fname)
            if os.path.isdir(os.path.join(CASES_DIR, d)) and os.path.exists(sub):
                return True
        # Fix 78: deep repro trees (nodejs/CVE-…/packages/server/routes/)
        if glob.glob(os.path.join(CASES_DIR, '**', fname), recursive=True):
            return True
        return False

    missing = [f for f in EXPECTATIONS if not _case_exists(f)]
    missing += [f for f in FORBIDDEN if not _case_exists(f)]
    if missing:
        print('GATE FAIL: expectation references missing case files:', missing)
        return 2

    # Fix 67: framework-scoped repros live in framework subdirectories
    # (e.g. symfony1/ carries its own core/lib/symfony marker so
    # detect_framework resolves per-subdir, not per-mixed-root).  Scan the
    # root (framework-agnostic repros) plus each framework subdir.
    scan_dirs = [CASES_DIR] + sorted(
        os.path.join(CASES_DIR, d) for d in os.listdir(CASES_DIR)
        if os.path.isdir(os.path.join(CASES_DIR, d)) and not d.startswith(('.'))
    )
    # Fix 110 (CVE-2026-126482): pin the hash seed — measured on t-osticket
    # 2026-11-18, unpinned runs flip ±11 verdicts purely from set-iteration
    # order (see tools/anchor_baseline.py Fix 110 note).  Gate expectations
    # must not depend on interpreter hash randomization.
    env = dict(os.environ, PYTHONPATH=REPO, PYTHONHASHSEED='0')
    tasks = []  # Fix 122: (scan_dir, task_id) pairs — forbidden scoping
    for scan_dir in scan_dirs:
        print(f'[cve-repro-gate] scanning {scan_dir} ...')
        # Fix 68: repros span languages (php root + java repros) — scan all
        # languages so java cases enter the graph; php-file semantics are
        # unchanged (their rules are php-scoped).  Root dir only; framework
        # subdirs (symfony1/) stay php-scoped as before.
        _lang68 = 'all' if scan_dir == CASES_DIR else 'php'
        # Fix 72: python repro subdirs (iot2050 config-file chain) scan as
        # python — the php default silently skipped them and the gate read 0.
        if scan_dir != CASES_DIR and glob.glob(os.path.join(scan_dir, '**', '*.py'), recursive=True):
            _lang68 = 'python'
        # Fix 78 (CVE-2026-41478): nodejs repro subdir scans as js — same
        # silent-skip trap as python above (php default → 0 rows → the
        # saltcorn expectation would read as an engine regression).
        if (scan_dir != CASES_DIR
                and not glob.glob(os.path.join(scan_dir, '**', '*.php'), recursive=True)
                and not glob.glob(os.path.join(scan_dir, '**', '*.py'), recursive=True)
                and glob.glob(os.path.join(scan_dir, '**', '*.js'), recursive=True)):
            _lang68 = 'js'
        # Fix 79 (CVE-2026-32613): java repro subdir scans as 'all' — the
        # php default silently skips .java files (same trap as python/js
        # above).  'all' keeps the root-scan semantics for the subdir.
        if (scan_dir != CASES_DIR
                and not glob.glob(os.path.join(scan_dir, '**', '*.php'), recursive=True)
                and not glob.glob(os.path.join(scan_dir, '**', '*.py'), recursive=True)
                and not glob.glob(os.path.join(scan_dir, '**', '*.js'), recursive=True)
                and glob.glob(os.path.join(scan_dir, '**', '*.java'), recursive=True)):
            _lang68 = 'all'
        proc = subprocess.run(
            [sys.executable, os.path.join(REPO, 'kunlun.py'), 'scan',
             '-t', scan_dir, '--yes', '-lan', _lang68, '--no-cache'],
            cwd=REPO, capture_output=True, text=True, env=env, timeout=2400)
        m = None
        for line in (proc.stdout + '\n' + proc.stderr).splitlines():
            if 'TaskID' in line:
                m = line.split('TaskID:')[1].strip().split()[0]
                m = m.replace('\x1b[0m', '').strip()
        if not m:
            print('GATE FAIL: could not read TaskID from scan output for', scan_dir)
            print(proc.stdout[-800:], proc.stderr[-400:])
            return 2
        tasks.append((scan_dir, int(m)))

    by_file = {}
    by_file_per_dir = {}  # Fix 122: scan_dir -> {base: {cvi: n}}
    for scan_dir, task_id in tasks:
        for r in ScanResultTask.objects.filter(scan_task_id=task_id):
            # vulfile_path may be stored relative AND suffixed ':lineno'
            # (e.g. 'CVE-...php:17') — strip both before basename matching.
            base = os.path.basename(str(r.vulfile_path).split(':')[0])
            by_file.setdefault(base, {}).setdefault(str(r.cvi_id), 0)
            by_file[base][str(r.cvi_id)] += 1
            by_file_per_dir.setdefault(scan_dir, {}).setdefault(base, {}).setdefault(str(r.cvi_id), 0)
            by_file_per_dir[scan_dir][base][str(r.cvi_id)] += 1

    failures = []
    for fname, expect in sorted(EXPECTATIONS.items()):
        got = by_file.get(fname, {})
        for cvi, want in sorted(expect.items()):
            have = got.get(cvi, 0)
            status = 'ok' if have >= want else 'FAIL'
            print(f'  [{status}] {fname}: CVI {cvi} expected>={want} got {have}')
            if have < want:
                failures.append(f'{fname}:{cvi}')
    # Fix 119g: negative expectations — must-have-ZERO rows (FP regressions).
    # Fix 122 (CVE-2026-124490): framework-scoped forbidden files evaluate
    # ONLY in their framework subdir scan.  The root pass is a deliberately
    # framework-agnostic mixed scan (Fix 67 subdir trap: a mixed root loses
    # per-subdir framework detection), so an openemr escape-helper contrast
    # fires there by design — the zero must hold in the scan where the
    # framework marker actually resolves (proved live: gate run 16:56 root
    # task 6592 fired contact_escape:19-21 while the openemr/ task had 0).
    def _forbidden_scope(fname):
        for h in glob.glob(os.path.join(CASES_DIR, '**', fname), recursive=True):
            rel = os.path.relpath(h, CASES_DIR)
            top = rel.split(os.sep)[0]
            if top != fname:  # lives inside a framework subdir
                return os.path.join(CASES_DIR, top)
        return None  # root-level file: every scan counts

    for fname, cvis in sorted(FORBIDDEN.items()):
        scope = _forbidden_scope(fname)
        got = by_file_per_dir.get(scope, {}) if scope else by_file
        for cvi in cvis:
            have = got.get(fname, {}).get(cvi, 0)
            status = 'ok' if have == 0 else 'FAIL'
            print(f'  [{status}] {fname}: CVI {cvi} expected==0 got {have}'
                  + (f' (scoped to {scope})' if scope else ''))
            if have:
                failures.append(f'{fname}:{cvi}:FP-regression')
    if failures:
        print(f'GATE FAIL: {len(failures)} expectation(s) not met: {failures}')
        print('→ investigate the engine change; do NOT lower the expectation')
        return 1
    print('GATE PASS: all CVE mini-repro expectations met')
    return 0


if __name__ == '__main__':
    sys.exit(main())
