const fs = require("fs");
const path = require("path");
const { chromium } = require("playwright");

// I2：mock 演示站全页面巡检。遍历静态导出的每一个页面，逐页打开，
// 记录脚本错误与「正文是否空」，产出台账所需的数字。
const BASE = process.env.MOCK_BASE || "http://127.0.0.1:3006";
// 巡检对象是「静态导出的每个页面」，默认指 mock 构建的输出目录；跑正式导出时改 OUT_DIR 即可。
const OUTDIR = process.env.OUT_DIR || "out";

function listRoutes(dir) {
  const out = [];
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      if (!e.isDirectory()) continue;
      if (e.name.startsWith("_") || e.name === "images" || e.name === "logo") continue;
      const p = path.join(d, e.name);
      if (fs.existsSync(path.join(p, "index.html"))) out.push("/" + path.relative(OUTDIR, p) + "/");
      walk(p);
    }
  };
  if (fs.existsSync(path.join(dir, "index.html"))) out.push("/");
  walk(dir);
  return [...new Set(out)].sort();
}

(async () => {
  const routes = listRoutes(OUTDIR);
  console.log("页面总数=" + routes.length);
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1500, height: 950 } });
  const bad = [];
  let empty = [];
  for (const r of routes) {
    const page = await ctx.newPage();
    const errs = [];
    page.on("pageerror", (e) => errs.push(String(e).split("\n")[0]));
    page.on("console", (m) => { if (m.type() === "error") errs.push("console: " + m.text().slice(0, 160)); });
    try {
      await page.goto(BASE + r, { waitUntil: "load", timeout: 20000 });
      await page.waitForTimeout(900);
      const main = page.locator("main");
      const text = (await main.count()) ? (await main.innerText()).replace(/\s+/g, " ") : "";
      if (text.length < 12) empty.push(r);
      const withData = text.length > 12;
      if (errs.length) bad.push({ r, errs: errs.slice(0, 3) });
      else if (r.includes("dashboard") || r === "/" || r.includes("findings") || r.includes("scans")) {
        console.log("  " + r + " 正文" + (withData ? "有内容(" + text.length + "字)" : "空"));
      }
    } catch (e) {
      bad.push({ r, errs: ["goto: " + String(e).split("\n")[0]] });
    }
    await page.close();
  }
  console.log("有脚本错误的页面=" + bad.length);
  for (const b of bad) console.log("  " + b.r + " → " + b.errs.join(" ;; "));
  console.log("正文过短的页面=" + empty.length + (empty.length ? " → " + empty.join(" ") : ""));
  await browser.close();
})();
