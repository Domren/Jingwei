#!/usr/bin/env node
// D1 e2e 夹具：三种响应形态，用来证明浏览器验证能把「真的执行」和「只是出现在
// HTML 里」分开。只在本地回环起服务，不连外网。
//   /reflect?q=...  原样回显 → payload 应真的执行
//   /escape?q=...   HTML 转义 → 不执行，也不该被算成反射
//   /textarea?q=... 原样塞进 <textarea> → HTML 里有 payload，但不执行（典型误报）

'use strict';

const http = require('http');

const port = Number(process.argv[2] || 8791);

function escapeHTML(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const server = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://127.0.0.1');
  const q = u.searchParams.get('q') || '';
  res.setHeader('content-type', 'text/html; charset=utf-8');
  switch (u.pathname) {
    case '/reflect':
      res.end(`<!doctype html><html><body><div id="out">${q}</div></body></html>`);
      return;
    case '/escape':
      res.end(`<!doctype html><html><body><div id="out">${escapeHTML(q)}</div></body></html>`);
      return;
    case '/textarea':
      res.end(`<!doctype html><html><body><textarea>${q}</textarea></body></html>`);
      return;
    default:
      res.end('<!doctype html><html><body>ok</body></html>');
  }
});

server.listen(port, '127.0.0.1', () => {
  console.log('ready ' + port);
});
