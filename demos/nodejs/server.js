// Hello World demo — Node.js, no dependencies.
//
// GET shows a name form; POST answers "Hello, <name>!" in the middle of the page.
// GET /api/info answers the product info a control panel polls for liveness.
// Listens on $HOST:$PORT (default 0.0.0.0:8080) and serves HTTPS when the
// installer has put TLS_CERT_PATH / TLS_KEY_PATH in the environment.
'use strict';
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const querystring = require('querystring');

const RUNTIME = 'Node.js';
const VERSION = require('./package.json').version;
const TEMPLATE = fs.readFileSync(path.join(__dirname, 'hello.html'), 'utf8');

const FORM = '<h1>Hello World</h1><form method="post">' +
    '<input name="name" placeholder="Your name" autofocus required>' +
    '<button type="submit">Say hello</button></form>';

function escapeHtml(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#x27;');
}

function greeting(name) {
    return '<h1>Hello, ' + escapeHtml(name) + '!</h1><a href="/">Say hello again</a>';
}

function page(content) {
    return TEMPLATE.split('{{runtime}}').join(RUNTIME).split('{{content}}').join(content);
}

function reply(res, text, contentType) {
    const body = Buffer.from(text, 'utf8');
    res.writeHead(200, { 'Content-Type': (contentType || 'text/html') + '; charset=utf-8', 'Content-Length': body.length });
    res.end(body);
}

function handler(req, res) {
    if (req.method === 'GET' && req.url.split('?')[0] === '/api/info') {
        const info = { productName: 'Hello ' + RUNTIME, version: VERSION, runtime: 'Node.js ' + process.version };
        return reply(res, JSON.stringify(info), 'application/json');
    }
    if (req.method !== 'POST') return reply(res, page(FORM));
    const chunks = [];
    req.on('data', function (c) { chunks.push(c); });
    req.on('end', function () {
        const fields = querystring.parse(Buffer.concat(chunks).toString('utf8'));
        const raw = Array.isArray(fields.name) ? fields.name[0] : fields.name;
        const name = String(raw || '').trim() || 'World';
        reply(res, page(greeting(name)));
    });
}

const host = process.env.HOST || '0.0.0.0';
const port = Number(process.env.PORT) || 8080;
const cert = process.env.TLS_CERT_PATH;
const key = process.env.TLS_KEY_PATH;
const server = (cert && key)
    ? https.createServer({ cert: fs.readFileSync(cert), key: fs.readFileSync(key) }, handler)
    : http.createServer(handler);
server.listen(port, host, function () {
    console.log('Hello World (' + RUNTIME + ') listening on ' + (cert && key ? 'https' : 'http') + '://' + host + ':' + port);
});
