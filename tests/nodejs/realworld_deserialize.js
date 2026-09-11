/**
 * Real-world Unsafe Deserialization test cases for Kunlun-M scanner
 * Tests: node-serialize, node-v8-serialize unserialize() with user-controlled data
 */

const express = require('express');
const serialize = require('node-serialize');
const router = express.Router();

router.use(express.json());
router.use(express.urlencoded({ extended: true }));

/**
 * VULN: Unsafe deserialization via node-serialize.unserialize with req.body
 * Attacker can craft a serialized object that executes arbitrary code when deserialized
 * node-serialize's unserialize() can execute __defineGetter__ payloads
 * Example POST: {"data": '{"___class":"Function","___args":"","___code":"return require(\\\"child_process\\\").execSync(\\\"id\\\")"}'}
 */
router.post('/session-restore', (req, res) => {
    const sessionData = req.body.data;
    try {
        // VULN: Unserialize user-controlled data - allows RCE via crafted payloads
        const session = serialize.unserialize(sessionData);
        res.json({ session });
    } catch (err) {
        res.status(400).send('Invalid session data');
    }
});

/**
 * VULN: Unsafe deserialization via node-serialize with req.query token
 * Deserializing a base64-encoded serialized object from query params
 * Example: /auth?token=<base64-encoded malicious serialized object>
 */
router.get('/auth', (req, res) => {
    const token = req.query.token;
    try {
        // VULN: Deserializing user-supplied token without validation
        const decoded = Buffer.from(token, 'base64').toString();
        const session = serialize.unserialize(decoded);
        if (session && session.userId) {
            res.json({ authenticated: true, user: session.userId });
        } else {
            res.status(401).send('Invalid token');
        }
    } catch (err) {
        res.status(401).send('Authentication failed');
    }
});

/**
 * VULN: Unsafe deserialization via node-serialize with req.params
 * Attacker can inject via URL parameters
 * Example: /restore/<base64 encoded malicious serialized payload>
 */
router.get('/restore/:data', (req, res) => {
    const data = req.params.data;
    try {
        // VULN: Deserializing URL parameter directly
        const obj = serialize.unserialize(data);
        res.json(obj);
    } catch (err) {
        res.status(400).send('Restore failed');
    }
});

/**
 * SAFE: Using JSON.parse instead of unserialize
 * JSON.parse only handles primitive types and plain objects - no code execution possible
 */
router.post('/safe-session', (req, res) => {
    const sessionData = req.body.data;
    try {
        // SAFE: JSON.parse only handles data types, cannot execute code
        const session = JSON.parse(sessionData);
        // Additional validation: ensure it's a plain object with expected fields
        if (typeof session !== 'object' || session === null || Array.isArray(session)) {
            return res.status(400).send('Invalid session format');
        }
        if (typeof session.userId !== 'string' || typeof session.role !== 'string') {
            return res.status(400).send('Missing required session fields');
        }
        res.json({ session });
    } catch (err) {
        res.status(400).send('Invalid session data');
    }
});

/**
 * SAFE: Using JSON.parse with schema validation
 * Validate the parsed object structure before using it
 */
router.get('/safe-auth', (req, res) => {
    const token = req.query.token;
    try {
        // SAFE: Parse as JSON (not serialized object), then validate structure
        const decoded = Buffer.from(token, 'base64').toString();
        const session = JSON.parse(decoded);
        // Strict type checking prevents prototype pollution and unexpected objects
        const allowedRoles = ['user', 'admin', 'viewer'];
        if (typeof session.userId !== 'number' ||
            typeof session.expiresAt !== 'number' ||
            !allowedRoles.includes(session.role)) {
            return res.status(401).send('Invalid token structure');
        }
        if (Date.now() > session.expiresAt) {
            return res.status(401).send('Token expired');
        }
        res.json({ authenticated: true, user: session.userId, role: session.role });
    } catch (err) {
        res.status(401).send('Authentication failed');
    }
});

module.exports = router;
