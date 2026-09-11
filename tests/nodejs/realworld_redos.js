/**
 * Real-world ReDoS (Regular Expression Denial of Service) test cases for Kunlun-M scanner
 * Tests: new RegExp() with user-controlled input creating catastrophic backtracking patterns
 */

const express = require('express');
const router = express.Router();

router.use(express.json());
router.use(express.urlencoded({ extended: true }));

/**
 * VULN: ReDoS via new RegExp with req.query pattern
 * Attacker can craft input that causes catastrophic backtracking
 * Example: /search?pattern=(a+)+$  with input "aaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
 */
router.get('/search', (req, res) => {
    const pattern = req.query.pattern;
    const text = req.query.text || 'some test text here';
    try {
        // VULN: User-supplied regex pattern used directly without validation
        const regex = new RegExp(pattern);
        const matches = text.match(regex);
        res.json({ matches: matches || [] });
    } catch (err) {
        res.status(400).send('Invalid regex');
    }
});

/**
 * VULN: ReDoS via new RegExp with req.body pattern for validation
 * Attacker provides a malicious regex pattern that causes exponential backtracking
 * Example POST: {"pattern": "^(a+)+$", "input": "aaaaaaaaaaaaaaaaaaaaab"}
 */
router.post('/validate', (req, res) => {
    const { pattern, input } = req.body;
    try {
        // VULN: User-controlled regex with user-controlled input
        const regex = new RegExp(pattern);
        const isValid = regex.test(input);
        res.json({ valid: isValid });
    } catch (err) {
        res.status(400).send('Invalid regex');
    }
});

/**
 * VULN: ReDoS via RegExp constructor in middleware with req.params
 * Crafting a pattern like (\d|\w)+X with input of many matching chars
 * causes exponential backtracking when the last char doesn't match X
 */
router.get('/filter/:pattern', (req, res) => {
    const pattern = req.params.pattern;
    const testData = req.body.data;
    try {
        // VULN: User-supplied regex used to filter data
        const regex = new RegExp(pattern, 'g');
        const filtered = testData.filter(item => regex.test(item));
        res.json({ filtered });
    } catch (err) {
        res.status(400).send('Invalid pattern');
    }
});

/**
 * SAFE: Escape regex special characters before constructing RegExp
 * User input is treated as literal text, not as regex metacharacters
 */
router.get('/safe-search', (req, res) => {
    const searchTerm = req.query.term;
    const text = req.query.text || 'some test text here';
    // SAFE: Escape all regex special characters from user input
    const escapeRegex = (str) => {
        return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    };
    const escapedTerm = escapeRegex(searchTerm);
    const regex = new RegExp(escapedTerm);
    const matches = text.match(regex);
    res.json({ matches: matches || [] });
});

/**
 * SAFE: Use string methods (includes, indexOf) instead of RegExp for literal search
 * No regex engine involved, so no backtracking possible
 */
router.post('/safe-validate', (req, res) => {
    const { term, input } = req.body;
    // SAFE: Use simple string comparison instead of regex
    // No risk of catastrophic backtracking with string methods
    const isValid = typeof input === 'string' && input.includes(term);
    // Or for exact match: const isValid = input === term;
    res.json({ valid: isValid, term, input });
});

module.exports = router;
