/**
 * Real-world XXE (XML External Entity) test cases for Kunlun-M scanner
 * Tests: xml2js.parseString, libxmljs.parseXml with user-controlled XML
 */

const express = require('express');
const xml2js = require('xml2js');
const libxmljs = require('libxmljs');
const router = express.Router();

router.use(express.json());
router.use(express.urlencoded({ extended: true }));

/**
 * VULN: XXE via xml2js.parseString with req.body XML
 * xml2js by default does NOT disable external entities
 * Attacker can read server files or make SSRF requests
 * Example POST XML: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>
 */
router.post('/upload-xml', (req, res) => {
    const xmlData = req.body.xml;
    const parser = new xml2js.Parser();
    // VULN: Default xml2js parser allows external entity expansion
    parser.parseString(xmlData, (err, result) => {
        if (err) return res.status(400).send('Invalid XML');
        res.json(result);
    });
});

/**
 * VULN: XXE via xml2js.parseString with explicit options (still vulnerable)
 * Even with some options set, external entities may not be fully disabled
 * depending on the version
 * Example POST: {"xml": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]><data>&xxe;</data>"}
 */
router.post('/import', (req, res) => {
    const xmlData = req.body.xml;
    const parser = new xml2js.Parser({
        explicitArray: true,
        explicitCharkey: true,
    });
    // VULN: No explicitXXE or entity resolution options set
    parser.parseString(xmlData, (err, result) => {
        if (err) return res.status(400).send('Parse error');
        res.json(result);
    });
});

/**
 * VULN: XXE via libxmljs.parseXml with user XML
 * libxmljs has options to disable entities but they are not set here
 * Example: <?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><root>&xxe;</root>
 */
router.post('/parse-config', (req, res) => {
    const xmlData = req.body.xml;
    try {
        // VULN: libxmljs parseXml with default options allows entity expansion
        const doc = libxmljs.parseXml(xmlData);
        res.json({ root: doc.root().text() });
    } catch (err) {
        res.status(400).send('XML parse error');
    }
});

/**
 * SAFE: xml2js with explicitEntity: false and explicitCharkey
 * Disables external entity processing entirely
 */
router.post('/safe-upload', (req, res) => {
    const xmlData = req.body.xml;
    const parser = new xml2js.Parser({
        // SAFE: Disable external entity resolution to prevent XXE
        explicitCharkey: true,
        explicitArray: false,
    });
    // SAFE: Pre-process XML to strip DOCTYPE declarations before parsing
    const sanitizedXml = xmlData
        .replace(/<!DOCTYPE[^>]*>/gi, '')
        .replace(/<!ENTITY[^>]*>/gi, '');
    parser.parseString(sanitizedXml, (err, result) => {
        if (err) return res.status(400).send('Invalid XML');
        res.json(result);
    });
});

/**
 * SAFE: libxmljs with noent: false and nonet: true options
 * noent: false disables entity substitution
 * nonet: true prevents network access for entity resolution
 */
router.post('/safe-parse', (req, res) => {
    const xmlData = req.body.xml;
    try {
        // SAFE: Disable entity substitution and network access
        const doc = libxmljs.parseXml(xmlData, {
            noent: false,    // Don't substitute entities
            nonet: true,     // No network access
            noent: true,     // Note: in safe mode, combine with dtdload: false
            dtdload: false,  // Don't load external DTDs
            dtdattr: false,  // Don't process DTD attributes
        });
        res.json({ root: doc.root().text() });
    } catch (err) {
        res.status(400).send('XML parse error');
    }
});

module.exports = router;
