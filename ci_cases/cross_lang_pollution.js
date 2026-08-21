// This file exists to test cross-language taint isolation.
// app.get is a safe Express route handler — it should NOT
// cause cross_lang_pollution.py's os.system() to be suppressed.
var express = require('express');
var app = express();

app.get('/safe', function(req, res) {
    res.send('ok');
});

app.listen(3000);
