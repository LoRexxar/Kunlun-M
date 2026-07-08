/**
 * Real-world Code Injection test cases for Kunlun-M scanner
 * Tests: eval(), vm.runInContext(), vm.runInNewContext() with user-controlled input
 */

const express = require('express');
const vm = require('vm');
const router = express.Router();

router.use(express.json());
router.use(express.urlencoded({ extended: true }));

/**
 * VULN: Code injection via eval() with req.body expression
 * Attacker can execute arbitrary JavaScript on the server
 * Example POST: {"expression": "require('child_process').execSync('id').toString()"}
 */
router.post('/calculate', (req, res) => {
    const expression = req.body.expression;
    try {
        const result = eval(expression);
        res.json({ result });
    } catch (err) {
        res.status(400).send('Invalid expression');
    }
});

/**
 * VULN: Code injection via vm.runInContext with req.query code
 * Even vm.runInContext can escape the sandbox in older Node.js versions
 * Example: /sandbox?code=process.exit()
 */
router.get('/sandbox', (req, res) => {
    const code = req.query.code;
    try {
        const context = vm.createContext({ console, Math });
        const result = vm.runInContext(code, context);
        res.json({ result });
    } catch (err) {
        res.status(400).send('Execution error');
    }
});

/**
 * VULN: Code injection via vm.runInNewContext with req.body formula
 * Attacker can craft payloads to escape the VM sandbox
 * Example POST: {"formula": "this.constructor.constructor('return process')().mainModule.require('child_process').execSync('whoami')"}
 */
router.post('/formula-eval', (req, res) => {
    const formula = req.body.formula;
    try {
        const sandbox = { x: 10, y: 20 };
        const result = vm.runInNewContext(formula, sandbox);
        res.json({ result });
    } catch (err) {
        res.status(400).send('Formula error');
    }
});

/**
 * SAFE: Simple math operation without eval
 * Parse numeric input and perform operations safely without code execution
 */
router.post('/safe-calculate', (req, res) => {
    const { a, b, op } = req.body;
    // SAFE: Whitelist allowed operations, parse as floats, no eval
    const numA = parseFloat(a);
    const numB = parseFloat(b);
    if (isNaN(numA) || isNaN(numB)) {
        return res.status(400).send('Invalid numbers');
    }
    let result;
    switch (op) {
        case 'add': result = numA + numB; break;
        case 'sub': result = numA - numB; break;
        case 'mul': result = numA * numB; break;
        case 'div':
            if (numB === 0) return res.status(400).send('Division by zero');
            result = numA / numB;
            break;
        default:
            return res.status(400).send('Unsupported operation');
    }
    res.json({ result });
});

/**
 * SAFE: Use a dedicated math expression parser library instead of eval
 * Example uses mathjs which safely parses and evaluates math expressions
 */
router.post('/safe-formula', (req, res) => {
    const formula = req.body.formula;
    // SAFE: Using a dedicated expression parser (mathjs or similar) that
    // does not evaluate arbitrary JavaScript
    // In production, use: const result = math.evaluate(formula, { x: 10, y: 20 });
    // For this test, we show the safe pattern - whitelist-based evaluation
    const allowed = /^[\d+\-*/().%\s]+$/;
    if (!allowed.test(formula)) {
        return res.status(400).send('Invalid formula');
    }
    // Use mathjs or similar safe evaluator in production
    try {
        const math = require('mathjs');
        const result = math.evaluate(formula, { x: 10, y: 20 });
        res.json({ result });
    } catch (err) {
        res.status(400).send('Formula evaluation error');
    }
});

module.exports = router;
