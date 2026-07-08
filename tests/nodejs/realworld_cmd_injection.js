/**
 * Real-world Command Injection test cases for Kunlun-M scanner
 * Tests: exec, execSync, execFile with user-controlled input concatenation
 */

const express = require('express');
const { exec, execSync, execFile } = require('child_process');
const router = express.Router();

// Middleware to parse body
router.use(express.json());
router.use(express.urlencoded({ extended: true }));

/**
 * VULN: Command injection via exec with req.query concatenation
 * Attacker can inject shell metacharacters like ; && || ` etc.
 * Example: /ping?host=127.0.0.1;cat%20/etc/passwd
 */
router.get('/ping', (req, res) => {
    const host = req.query.host;
    exec(`ping -c 3 ${host}`, (err, stdout) => {
        if (err) return res.status(500).send('Error');
        res.send(stdout);
    });
});

/**
 * VULN: Command injection via execSync with req.body concatenation
 * Attacker can inject via the filename parameter
 * Example POST: {"filename": "test.txt; rm -rf /"}
 */
router.post('/backup', (req, res) => {
    const filename = req.body.filename;
    try {
        const output = execSync(`tar -czf /backups/${filename}.tar.gz /data`);
        res.send('Backup created: ' + output.toString());
    } catch (err) {
        res.status(500).send('Backup failed');
    }
});

/**
 * VULN: Command injection via execFile with req.params concatenation
 * execFile with shell: true is also vulnerable
 */
router.get('/diagnose/:hostname', (req, res) => {
    const hostname = req.params.hostname;
    execFile('sh', ['-c', `traceroute ${hostname}`], (err, stdout) => {
        if (err) return res.status(500).send('Diagnosis failed');
        res.send(stdout);
    });
});

/**
 * SAFE: Input validation with allowlist pattern
 * Only allows alphanumeric, dots, and hyphens in hostnames
 */
router.get('/nslookup', (req, res) => {
    const host = req.query.host;
    // SAFE: Strict allowlist validation prevents injection
    const hostnameRegex = /^[a-zA-Z0-9.-]+$/;
    if (!hostnameRegex.test(host)) {
        return res.status(400).send('Invalid hostname');
    }
    exec(`nslookup ${host}`, (err, stdout) => {
        if (err) return res.status(500).send('Lookup failed');
        res.send(stdout);
    });
});

/**
 * SAFE: execFile with array arguments (no shell), input validated
 * execFile without shell does not interpret metacharacters
 */
router.get('/whois/:domain', (req, res) => {
    const domain = req.params.domain;
    const domainRegex = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!domainRegex.test(domain)) {
        return res.status(400).send('Invalid domain');
    }
    // SAFE: Using execFile with argument array avoids shell injection
    execFile('whois', [domain], (err, stdout) => {
        if (err) return res.status(500).send('Whois failed');
        res.send(stdout);
    });
});

module.exports = router;
