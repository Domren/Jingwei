const fs = require("fs");
const path = require("path");
const { chromium } = require("playwright");

// I2 巡检 + I4 视觉验证：遍历静态导出的每一个页面，逐页打开，记下脚本错误、正文长度，
// 并给每个页面留一张截图。
//
// 为什么值得为这件事装一个浏览器：静态导出的页面在「构建通过」与「打开是红的」之间没有任何
// 自动化能区分——路由少一个参数、某个组件在服务端取不到 props、mock 数据形状对不上，
// `next build` 全都照过，用户点开才是空白或崩溃。这一层跑的是真 Chromium，看的是真渲染结果。
//
// 口径（发版必过项就靠这三条）：
//   1. 控制台报错 / 未捕获异常 → 失败；
//   2. 正文空到没有可读内容 → 失败（除非列在 ALLOW_EMPTY 里，理由会打进报告）；
//   3. 页面渲染出 Next 的红色错误块 → 失败。
// 这一层证明的是「页面能渲染、没有脚本报错」，不证明业务数据正确：跑的是 mock 构建，
// 没有后端、没有靶机，也不点任何真会发包的按钮。
const BASE = process.env.MOCK_BASE || "http://127.0.0.1:3006";
// 巡检对象是「静态导出的每个页面」，默认指 mock 构建的输出目录；跑正式导出时改 OUT_DIR 即可。
const OUTDIR = process.env.OUT_DIR || "out";
const SHOTS = process.env.JW_SHOTS || "shots";
const REPORT = process.env.UI_REPORT || "";
// 允许正文为空的页面（前缀匹配）。空着的页面不该静默通过，但「这一页在这轮本来就没内容」
// 需要显式登记，登记了就等于有人看过并认可。
const ALLOW_EMPTY = (process.env.ALLOW_EMPTY || "").split(",").map((s) => s.trim()).filter(Boolean);
// 正文低于这个字数算「没渲染出可读内容」。12 是 I2 那轮按最短的真实空态文案定的。
const MIN_TEXT = Number(process.env.MIN_TEXT || 12);

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

// 截图名要把路由摊平：CI 产物是拍平的一堆文件，层级目录名里的斜杠在这里没法用。
function shotName(route) {
  const flat = route.replace(/^\/+|\/+$/g, "").replace(/\//g, "-");
  return (flat || "index") + ".png";
}

(async () => {
  const routes = listRoutes(OUTDIR);
  if (routes.length === 0) {
    console.error(`在 ${OUTDIR} 里没找到任何导出页面——构建没跑、还是输出目录指错了？`);
    process.exit(1);
  }
  fs.mkdirSync(SHOTS, { recursive: true });
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1500, height: 950 } });
  const rows = [];
  const failures = [];
  for (const r of routes) {
    const page = await ctx.newPage();
    const errs = [];
    page.on("pageerror", (e) => errs.push("异常: " + String(e).split("\n")[0]));
    page.on("console", (m) => {
      if (m.type() === "error") errs.push("console: " + m.text().slice(0, 160));
    });
    const row = { route: r, shot: shotName(r), text: 0, scope: "body", errs: [], crash: "", skipped: false };
    try {
      await page.goto(BASE + r, { waitUntil: "load", timeout: 20000 });
      await page.waitForTimeout(900);
      // 应用外壳里的页面量 <main>；404 这类壳外页面没有 main，量整页。
      // 退到 body 不是放宽判据——真崩掉的页面 body 里也没有可读文字——而报告里会标出来，
      // 免得「404 页正文 0 字」被当成一个需要豁免的空页面。
      const main = page.locator("main");
      const inside = (await main.count()) > 0;
      const text = (await page.locator(inside ? "main" : "body").first().innerText()).replace(/\s+/g, " ");
      row.scope = inside ? "main" : "body";
      row.text = text.length;
      // Next 的客户端错误页正文并不空（有一大段堆栈），只按字数判会放过去。
      if (/Application error|Unhandled Runtime Error|Internal Server Error/.test(text)) {
        row.crash = "页面渲染出 Next 错误块";
      }
      await page.screenshot({ path: path.join(SHOTS, row.shot), fullPage: false });
    } catch (e) {
      row.errs.push("goto: " + String(e).split("\n")[0]);
    }
    row.errs.push(...errs.slice(0, 3));
    if (row.text < MIN_TEXT) {
      const allowed = ALLOW_EMPTY.some((p) => r.startsWith(p));
      row.skipped = allowed;
      if (!allowed) row.errs.push(`正文只有 ${row.text} 字（空页面）`);
    }
    if (row.crash) row.errs.push(row.crash);
    if (row.errs.length) failures.push(row);
    rows.push(row);
    await page.close();
  }
  await browser.close();

  const lines = [
    "# 界面视觉验证（mock 静态导出）",
    "",
    `- 页面总数=${rows.length}　截图目录=${SHOTS}`,
    `- 有问题的页面=${failures.length}`,
    `- 允许空正文的页面=${rows.filter((x) => x.skipped).length}`,
    "",
    "| 页面 | 正文字数 | 截图 | 问题 |",
    "| :-- | --: | :-- | :-- |",
    ...rows.map(
      (x) =>
        `| ${x.route} | ${x.text}${x.scope === "main" ? "" : "（量整页）"} | ${x.shot} | ${
          x.errs.join(" ;; ") || (x.skipped ? "空正文（已登记）" : "—")
        } |`,
    ),
  ];
  const md = lines.join("\n") + "\n";
  if (REPORT) fs.writeFileSync(REPORT, md);
  console.log(md);
  if (failures.length) {
    console.error(`视觉验证未过：${failures.length} 个页面有问题，详见上面表格与 ${SHOTS} 里的截图`);
    process.exit(1);
  }
  console.log(`视觉验证通过：${rows.length} 个页面全部渲染、无脚本错误`);
})();
