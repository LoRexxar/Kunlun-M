/**
 * Real-world Open Redirect test cases for Kunlun-M scanner
 * Tests: res.redirect() with user-controlled URL from query/body/params
 */

const express = require('express');
const router = express.Router();

router.use(express.json());
router.use(express.urlencoded({ extended: true }));

/**
 * VULN: Open redirect via res.redirect with req.query URL
 * Attacker can redirect users to phishing sites
 * Example: /redirect?url=https://evil.com/phishing
 */
router.get('/redirect', (req, res) => {
    const targetUrl = req.query.url;
    // VULN: Unvalidated user-controlled URL passed directly to redirect
    res.redirect(targetUrl);
});

/**
 * VULN: Open redirect via res.redirect with req.body next parameter
 * Common in login flows where attacker provides a malicious "next" URL
 * Example POST: {"next": "https://attacker.com/fake-login"}
 */
router.post('/login', (req, res) => {
    const { username, password, next } = req.body;
    // Simulated auth check
    if (username === 'admin' && password === 'admin123') {
        // VULN: Redirect to user-supplied URL without validation
        res.redirect(next || '/dashboard');
    } else {
        res.status(401).send('Invalid credentials');
    }
});

/**
 * VULN: Open redirect via res.redirect with req.params with // bypass
 * Some frameworks strip leading // but not all
 * Example: /goto/https://evil.com (or //evil.com via protocol-relative)
 */
router.get('/goto/:target', (req, res) => {
    const target = req.params.target;
    // VULN: User-controlled target used in redirect without validation
    res.redirect(target);
});

/**
 * SAFE: Relative redirect only - use a whitelist of allowed paths
 * Prevents redirection to external domains
 */
router.get('/safe-redirect', (req, res) => {
    const target = req.query.url;
    // SAFE: Only allow relative redirects (starting with /)
    // Block any URL with a protocol or hostname
    if (!target || target.startsWith('http://') || target.startsWith('https://') ||
        target.startsWith('//') || target.startsWith('\\\\')) {
        return res.redirect('/home');
    }
    // Additionally verify it starts with / and is a known safe path
    const safePaths = ['/home', '/dashboard', '/profile', '/settings'];
    if (safePaths.some(p => target.startsWith(p))) {
        res.redirect(target);
    } else {
        res.redirect('/home');
    }
});

/**
 * SAFE: URL whitelist validation before redirect
 * Only specific pre-approved URLs are allowed as redirect destinations
 */
router.post('/safe-login', (req, res) => {
    const { username, password, next } = req.body;
    if (username === 'admin' && password === 'admin123') {
        // SAFE: Whitelist of allowed redirect destinations
        const allowedRedirects = ['/dashboard', '/home', '/profile', '/settings'];
        const redirectTarget = allowedRedirects.includes(next) ? next : '/dashboard';
        res.redirect(redirectTarget);
    } else {
        res.status(401).send('Invalid credentials');
    }
});

module.exports = router;
