/**
 * Real-world SQL Injection test cases for Kunlun-M scanner
 * Tests: .query() with string concatenation, .raw() with template literal injection
 */

const express = require('express');
const knex = require('knex')({ client: 'mysql2', connection: {} });
const { Pool } = require('pg');
const pool = new Pool();
const router = express.Router();

router.use(express.json());
router.use(express.urlencoded({ extended: true }));

/**
 * VULN: SQL injection via knex.raw() with req.query string concatenation
 * Attacker can extract data via UNION or manipulate queries
 * Example: /users?search=' UNION SELECT password FROM admins --
 */
router.get('/users', async (req, res) => {
    const search = req.query.search;
    try {
        const results = await knex.raw(`SELECT * FROM users WHERE name LIKE '%${search}%'`);
        res.json(results);
    } catch (err) {
        res.status(500).send('Query failed');
    }
});

/**
 * VULN: SQL injection via pg Pool.query() with req.body string concatenation
 * Attacker can bypass authentication or extract sensitive data
 * Example POST: {"username": "admin' OR '1'='1", "password": "anything"}
 */
router.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query(
            `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`
        );
        if (result.rows.length > 0) {
            res.json({ success: true, user: result.rows[0] });
        } else {
            res.status(401).send('Invalid credentials');
        }
    } catch (err) {
        res.status(500).send('Login error');
    }
});

/**
 * VULN: SQL injection via knex.raw() with req.params concatenation
 * Attacker can inject SQL via the order parameter
 * Example: /products/desc; DROP TABLE products; --
 */
router.get('/products/:order', async (req, res) => {
    const order = req.params.order;
    try {
        const results = await knex.raw(`SELECT * FROM products ORDER BY price ${order}`);
        res.json(results);
    } catch (err) {
        res.status(500).send('Query failed');
    }
});

/**
 * SAFE: Parameterized query using knex binding syntax
 * User input is properly escaped and treated as a value, not SQL
 */
router.get('/safe-users', async (req, res) => {
    const search = req.query.search;
    try {
        // SAFE: Using parameterized query with bindings prevents SQL injection
        const results = await knex.raw('SELECT * FROM users WHERE name LIKE ?', [`%${search}%`]);
        res.json(results);
    } catch (err) {
        res.status(500).send('Query failed');
    }
});

/**
 * SAFE: Parameterized query using pg Pool with $1 placeholder
 * User input is safely passed as a parameter, not concatenated into SQL
 */
router.post('/safe-login', async (req, res) => {
    const { username, password } = req.body;
    try {
        // SAFE: Using $1/$2 parameterized placeholders prevents SQL injection
        const result = await pool.query(
            'SELECT * FROM users WHERE username = $1 AND password = $2',
            [username, password]
        );
        if (result.rows.length > 0) {
            res.json({ success: true, user: result.rows[0] });
        } else {
            res.status(401).send('Invalid credentials');
        }
    } catch (err) {
        res.status(500).send('Login error');
    }
});

module.exports = router;
