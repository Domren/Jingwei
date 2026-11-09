#!/usr/bin/env node
// 浏览器真实验证 XSS：把一个「dalfox 说可执行」的 PoC URL 真正放进 Chromium 里加载，
// 以「是否真的执行了 JS」为准，而不是以「payload 出现在响应里」为准。
//
// 判定信号（任一成立即 executed）：
//   1) 页面弹出 dialog（alert/confirm/prompt）——dalfox 的 PoC 基本都用 alert；
//   2) 第二遍把 payload 换成 marker 载荷后，window.__jw_marker 被写上——证明 JS 执行；
//   3) 未捕获异常里带 marker（some payloads throw before dialog）。
//
// 只做 GET/URL 载体：POST body、Cookie、Header 注入点的「真实执行」需要自动提交表单，
// 本脚本不假装支持，调用方应如实标注「未浏览器验证」。
//
// 用法：node verify.cjs input.json
// 输入：{"timeout_ms":15000,"targets":[{"url":"...","payload":"..."}]}
// 输出（单行 JSON）：{"version":"1.64.1","results":[{...}]}

'use strict';

const fs = require('fs');

function loadPlaywright() {
  const candidates = [];
  if (process.env.JW_PLAYWRIGHT_MODULE) candidates.push(process.env.JW_PLAYWRIGHT_MODULE);
  candidates.push('playwright', 'playwright-core');
  const failures = [];
  for (const c of candidates) {
    try {
      return require(c);
    } catch (e) {
      failures.push(`${c}: ${e.message}`);
    }
  }
  throw new Error('playwright 模块不可用（' + failures.join(' | ') + '）');
}

function decodeOnce(s) {
  try {
    return decodeURIComponent(s.replace(/\+/g, ' '));
  } catch (e) {
    return s;
  }
}

// replacePayload 在 URL 里按「原样 / URL 编码 / 表单编码」三种形态替换注入载荷。
function replacePayload(url, payload, replacement) {
  if (!payload) return '';
  const forms = [payload, encodeURIComponent(payload), encodeURIComponent(payload).replace(/%20/g, '+')];
  for (const f of forms) {
    if (f && url.includes(f)) return url.split(f).join(encodeURIComponent(replacement));
  }
  return '';
}

function markerPayload(marker) {
  return `<img src=x onerror="window.__jw_marker='${marker}'">`;
}

async function verifyOne(browser, target, timeoutMs) {
  const marker = 'jw' + Math.random().toString(36).slice(2, 10);
  const started = Date.now();
  const signals = [];
  const dialogs = [];
  let error = '';
  let reflected = false;
  let finalURL = target.url;
  let executed = false;
  let markerHit = '';
  let markerTried = false;

  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  try {
    const page = await context.newPage();
    page.on('dialog', async (d) => {
      dialogs.push(`${d.type()}:${d.message()}`);
      signals.push(`dialog:${d.type()}`);
      executed = true;
      try {
        await d.dismiss();
      } catch (e) {
        /* 弹窗可能已随页面关闭 */
      }
    });
    let pageErrors = [];
    page.on('pageerror', (e) => pageErrors.push(String((e && e.message) || e)));

    let docBody = '';
    try {
      const resp = await page.goto(target.url, { waitUntil: 'load', timeout: timeoutMs });
      if (resp) {
        try {
          docBody = await resp.text();
        } catch (e) {
          docBody = '';
        }
      }
    } catch (e) {
      error = String((e && e.message) || e);
    }
    await page.waitForTimeout(700);
    finalURL = page.url();

    // 反射要看「服务端返回的原始 HTML」：DOM 序列化会把 <textarea> 里的标签转义，
    // 拿 page.content() 判断会把「原样塞进 textarea」误判成没有反射。
    let html = docBody;
    if (!html) {
      try {
        html = await page.content();
      } catch (e) {
        html = '';
      }
    }
    if (target.payload) {
      const raw = target.payload;
      const decoded = decodeOnce(target.payload);
      reflected = html.includes(raw) || (decoded !== raw && html.includes(decoded));
    }
    if (pageErrors.some((m) => m.includes(marker))) {
      executed = true;
      signals.push('pageerror:marker');
    }

    // 第二遍：换成 marker 载荷重放。payload 没被执行（或被浏览器拦下）时，
    // 这一步能把「HTML 里有但不执行」与「真的执行了」区分开。
    const markedURL = replacePayload(target.url, target.payload, markerPayload(marker));
    if (!executed && markedURL) {
      markerTried = true;
      const p2 = await context.newPage();
      p2.on('dialog', async (d) => {
        dialogs.push(`${d.type()}:${d.message()}`);
        signals.push(`dialog:${d.type()}`);
        executed = true;
        try {
          await d.dismiss();
        } catch (e) {
          /* ignore */
        }
      });
      try {
        await p2.goto(markedURL, { waitUntil: 'load', timeout: timeoutMs });
        await p2.waitForTimeout(500);
        markerHit = String(await p2.evaluate(() => window.__jw_marker || ''));
      } catch (e) {
        if (!error) error = String((e && e.message) || e);
      }
      if (markerHit === marker) {
        executed = true;
        signals.push('dom:marker');
      }
      await p2.close().catch(() => {});
    }
  } finally {
    await context.close().catch(() => {});
  }

  return {
    url: target.url,
    executed,
    signals,
    dialogs,
    reflected,
    marker_tried: markerTried,
    marker_hit: markerHit === marker,
    final_url: finalURL,
    elapsed_ms: Date.now() - started,
    error,
  };
}

(async () => {
  const inputPath = process.argv[2];
  if (!inputPath) {
    console.log(JSON.stringify({ error: '缺少输入文件参数' }));
    process.exit(2);
  }
  let input;
  try {
    input = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
  } catch (e) {
    console.log(JSON.stringify({ error: '输入不是有效 JSON: ' + e.message }));
    process.exit(2);
  }
  const timeoutMs = Math.max(3000, Math.min(60000, Number(input.timeout_ms) || 15000));
  const targets = Array.isArray(input.targets) ? input.targets.slice(0, 20) : [];
  let playwright;
  try {
    playwright = loadPlaywright();
  } catch (e) {
    console.log(JSON.stringify({ error: e.message, missing: true }));
    process.exit(0);
  }
  let version = '';
  try {
    version = String(require('playwright/package.json').version || '');
  } catch (e) {
    /* 版本只用于取证 */
  }
  let browser;
  const results = [];
  try {
    browser = await playwright.chromium.launch({ headless: true });
    for (const t of targets) {
      if (!t || !t.url) continue;
      try {
        results.push(await verifyOne(browser, t, timeoutMs));
      } catch (e) {
        results.push({
          url: t.url,
          executed: false,
          signals: [],
          dialogs: [],
          reflected: false,
          elapsed_ms: 0,
          error: String((e && e.message) || e),
        });
      }
    }
  } catch (e) {
    console.log(JSON.stringify({ version, error: 'Chromium 启动失败: ' + String((e && e.message) || e) }));
    process.exit(0);
  } finally {
    if (browser) await browser.close().catch(() => {});
  }
  console.log(JSON.stringify({ version, results }));
})();
