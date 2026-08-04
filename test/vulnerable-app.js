// ⚠️ DELIBERATELY VULNERABLE TEST FILE — DO NOT DEPLOY ⚠️

const express = require('express');
const mysql = require('mysql');
const crypto = require('crypto');
const { exec } = require('child_process');
const fs = require('fs');
const jwt = require('jsonwebtoken');

const app = express();
const AWS_ACCESS_KEY = 'AKIA1234567890ABCDEF'; // Hardcoded AWS key
const dbPassword = 'admin123!'; // Hardcoded database password

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: dbPassword,
  database: 'myapp'
});

// VULN: SQL Injection — template literal in query
app.get('/user/:id', (req, res) => {
  const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
  connection.query(query, (err, results) => {
    if (err) return res.status(500).send('Error');
    res.json(results);
  });
});

// VULN: Command Injection — user input in exec
app.get('/ping', (req, res) => {
  const host = req.query.host;
  exec(`ping -c 3 ${host}`, (err, stdout) => {
    if (err) return res.status(500).send('Error');
    res.send(`<pre>${stdout}</pre>`);
  });
});

// VULN: XSS — innerHTML with user input
app.get('/profile', (req, res) => {
  const name = req.query.name;
  res.send(`
    <html>
    <body>
      <h1>Welcome</h1>
      <div id="greeting"></div>
      <script>
        document.getElementById('greeting').innerHTML = 'Hello, ' + '${name.replace(/'/g, "\\'")}';
      </script>
    </body>
    </html>
  `);
});

// VULN: Path Traversal — file read with user input
app.get('/download', (req, res) => {
  const filePath = req.query.file;
  fs.readFile(`./files/${filePath}`, (err, data) => {
    if (err) return res.status(404).send('Not found');
    res.send(data);
  });
});

// VULN: Insecure Crypto — MD5 hash
app.post('/hash', (req, res) => {
  const hash = crypto.createHash('md5').update(req.body.data).digest('hex');
  res.json({ hash });
});

// VULN: JWT with weak secret and no algorithm restriction
app.post('/login', (req, res) => {
  const token = jwt.sign({ user: req.body.username }, 'secret', { algorithm: 'HS256' });
  res.json({ token });
});

// VULN: Insecure Deserialization — eval with user input
app.post('/process', (req, res) => {
  const result = eval(`(${req.body.data})`);
  res.json({ result });
});

// VULN: Open Redirect
app.get('/redirect', (req, res) => {
  res.redirect(req.query.url);
});

// VULN: Prototype Pollution — unsafe merge
app.post('/config', (req, res) => {
  const config = {};
  Object.assign(config, req.body);
  res.json({ config });
});

// VULN: SSRF
const http = require('http');
app.get('/fetch', (req, res) => {
  const url = req.query.url;
  http.get(url, (response) => {
    let data = '';
    response.on('data', chunk => data += chunk);
    response.on('end', () => res.send(data));
  });
});

app.listen(3000);
