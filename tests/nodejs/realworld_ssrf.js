/**
 * Real-world SSRF test cases for Kunlun-M scanner
 * Tests: http.get, http.request, https.get with user-controlled URL
 */

const express = require('express');
const http = require('http');
const https = require('https');
const { URL } = require('url');
const router = express.Router();

router.use(express.json());
router.use(express.urlencoded({ extended: true }));

/**
 * VULN: SSRF via http.get with req.query URL
 * Attacker can request internal services like http://169.254.169.254/latest/meta-data/
 * Example: /proxy?url=http://localhost:6379/ (Redis), http://169.254.169.254/metadata
 */
router.get('/proxy', (req, res) => {
    const targetUrl = req.query.url;
    http.get(targetUrl, (proxyRes) => {
        let body = '';
        proxyRes.on('data', (chunk) => body += chunk);
        proxyRes.on('end', () => res.send(body));
    }).on('error', (err) => {
        res.status(500).send('Proxy request failed');
    });
});

/**
 * VULN: SSRF via http.request with req.body url and method
 * Attacker controls both method and URL, allowing full internal scanning
 * Example POST: {"url": "http://127.0.0.1:22", "method": "GET"}
 */
router.post('/webhook-test', (req, res) => {
    const { url, method } = req.body;
    const parsedUrl = new URL(url);
    const options = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || 80,
        path: parsedUrl.pathname,
        method: method || 'GET',
    };
    const proxyReq = http.request(options, (proxyRes) => {
        let body = '';
        proxyRes.on('data', (chunk) => body += chunk);
        proxyRes.on('end', () => res.json({ status: proxyRes.statusCode, body }));
    });
    proxyReq.on('error', () => res.status(500).send('Request failed'));
    proxyReq.end();
});

/**
 * VULN: SSRF via https.get with req.params URL
 * Attacker can probe internal HTTPS services
 * Example: /fetch/https://internal-admin:8443/admin
 */
router.get('/fetch/:targetUrl', (req, res) => {
    const encodedUrl = req.params.targetUrl;
    https.get(encodedUrl, (proxyRes) => {
        let body = '';
        proxyRes.on('data', (chunk) => body += chunk);
        proxyRes.on('end', () => res.send(body));
    }).on('error', () => res.status(502).send('Fetch failed'));
});

/**
 * SAFE: URL whitelist - only allow specific allowed domains
 * Prevents access to internal/localhost/metadata endpoints
 */
router.get('/safe-proxy', (req, res) => {
    const targetUrl = req.query.url;
    try {
        const parsed = new URL(targetUrl);
        const allowedHosts = ['api.github.com', 'api.example.com', 'api.publicdata.org'];
        // SAFE: Strict hostname whitelist prevents SSRF
        if (!allowedHosts.includes(parsed.hostname)) {
            return res.status(403).send('Domain not allowed');
        }
        // Also block private/internal IPs
        if (parsed.hostname === 'localhost' || /^10\./.test(parsed.hostname) ||
            /^172\.(1[6-9]|2\d|3[01])\./.test(parsed.hostname) ||
            /^192\.168\./.test(parsed.hostname)) {
            return res.status(403).send('Internal addresses not allowed');
        }
        http.get(targetUrl, (proxyRes) => {
            let body = '';
            proxyRes.on('data', (chunk) => body += chunk);
            proxyRes.on('end', () => res.send(body));
        }).on('error', () => res.status(502).send('Fetch failed'));
    } catch (e) {
        res.status(400).send('Invalid URL');
    }
});

/**
 * SAFE: Origin check - validate protocol and prevent private IP ranges
 */
router.post('/safe-webhook', (req, res) => {
    const { url } = req.body;
    try {
        const parsed = new URL(url);
        // SAFE: Only allow HTTPS to prevent internal network scanning
        if (parsed.protocol !== 'https:') {
            return res.status(400).send('Only HTTPS URLs allowed');
        }
        // Block internal/private IP addresses
        const ip = parsed.hostname;
        const privateRanges = ['localhost', '127.0.0.1', '0.0.0.0', '::1',
            '169.254.169.254', 'metadata.google.internal'];
        if (privateRanges.includes(ip) || ip.startsWith('10.') ||
            ip.startsWith('172.16.') || ip.startsWith('192.168.')) {
            return res.status(403).send('Private addresses blocked');
        }
        https.get(url, (proxyRes) => {
            let body = '';
            proxyRes.on('data', (chunk) => body += chunk);
            proxyRes.on('end', () => res.json({ status: proxyRes.statusCode, body }));
        }).on('error', () => res.status(502).send('Request failed'));
    } catch (e) {
        res.status(400).send('Invalid URL');
    }
});

module.exports = router;
