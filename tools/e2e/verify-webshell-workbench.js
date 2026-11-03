// 浏览器端到端验证 WebShell 工作台（终端 / 文件管理 / 系统信息），目标是 Ubuntu-1
// 靶机上真实落地的加密 v2 PHP 壳（Apache :8080）与 JSP 壳（Tomcat9 :8081）。
// 会话令牌从 /tmp/jw.token 读取，只注入浏览器上下文，不打印。
const { chromium } = require("playwright");
const fs = require("fs");
const path = require("path");

const BASE = process.env.JW_BASE || "http://127.0.0.1:9790";
const OUT = process.env.JW_SHOTS || "shots";
const PASS = [];
const FAIL = [];
const ok = (n) => { PASS.push(n); console.log("  OK   " + n); };
const bad = (n, d) => { FAIL.push(n + " — " + d); console.log("  FAIL " + n + " — " + d); };
const flat = (s) => s.replace(/\s+/g, " ").slice(0, 260);

async function shot(page, name) {
  await page.screenshot({ path: path.join(OUT, name), fullPage: false });
}

// 输出框是 dialog 里唯一的 bg-muted/30 容器，每轮命令追加一个 <pre>。忙闲只能看
// spinner：输入框为空时「执行」本来就 disabled，用它判断会永远等不到。
const countJS = () => {
  const box = Array.from(document.querySelectorAll('[role="dialog"] div')).find((d) =>
    String(d.className).includes("bg-muted/30")
  );
  return box ? box.querySelectorAll("pre").length : -1;
};

async function turnCount(page) {
  return page.evaluate(countJS);
}

async function waitTurn(page, before, ms = 110000) {
  await page.waitForFunction(
    (n) => {
      const box = Array.from(document.querySelectorAll('[role="dialog"] div')).find((d) =>
        String(d.className).includes("bg-muted/30")
      );
      if (!box) return false;
      if (document.querySelector("button svg.animate-spin")) return false;
      return box.querySelectorAll("pre").length > n;
    },
    before,
    { timeout: ms }
  );
  await page.waitForTimeout(300);
}

async function runCommand(page, cmd, timeoutLabel) {
  if (timeoutLabel) {
    await page.getByRole("combobox").last().click();
    await page.getByRole("option", { name: timeoutLabel }).click();
  }
  const before = await turnCount(page);
  const input = page.getByPlaceholder("命令，例如 id；cd 会保留在当前会话");
  await input.click();
  await input.fill(cmd);
  await input.press("Enter");
  await waitTurn(page, before);
  return await page.getByRole("dialog").innerText();
}

async function waitForDialogText(page, re, ms = 70000) {
  await page.waitForFunction(
    ({ source, flags }) => {
      const el = document.querySelector('[role="dialog"]');
      return !!el && new RegExp(source, flags).test(el.innerText);
    },
    { source: re.source, flags: re.flags },
    { timeout: ms }
  );
}

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const token = fs.readFileSync(process.env.JW_TOKEN_FILE || "/tmp/jw.token", "utf8").trim();
  const browser = await chromium.launch({ headless: true, args: ["--no-sandbox"] });
  const ctx = await browser.newContext({ viewport: { width: 1680, height: 1000 } });
  await ctx.addCookies([{ name: "jingwei_token", value: token, url: BASE }]);
  await ctx.addInitScript((t) => localStorage.setItem("jingwei_token", t), token);
  const page = await ctx.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));

  // 1) 列表页：两套壳都在；逐行点「检测」后都该是存活
  await page.goto(BASE + "/function/deep/webshells", { waitUntil: "networkidle", timeout: 60000 });
  await page.waitForTimeout(2500);
  const phpRow = page.locator("tr", { hasText: "tpl-render.php" });
  const jspRow = page.locator("tr", { hasText: "report-view.jsp" });
  (await phpRow.count()) === 1 ? ok("列表有 PHP 壳行") : bad("列表有 PHP 壳行", "行数=" + (await phpRow.count()));
  (await jspRow.count()) === 1 ? ok("列表有 JSP 壳行") : bad("列表有 JSP 壳行", "行数=" + (await jspRow.count()));
  for (const [label, row] of [
    ["PHP", phpRow],
    ["JSP", jspRow],
  ]) {
    await row.getByRole("button", { name: "检测" }).click();
    await page.waitForTimeout(6000);
    const txt = await row.innerText();
    txt.includes("存活") ? ok(label + " 检测后标记存活") : bad(label + " 检测后标记存活", flat(txt));
    txt.includes("加密 v2") ? ok(label + " 协议徽章写 v2") : bad(label + " 协议徽章写 v2", flat(txt));
  }
  const alive = await page.getByText("存活", { exact: true }).count();
  alive >= 2 ? ok("两条记录标记为存活（" + alive + "）") : bad("两条记录标记为存活", "徽章数=" + alive);
  await shot(page, "wb-01-list.png");

  // 2) PHP 终端：首条命令回传退出码与目标自己的目录
  await phpRow.getByTitle("工作台 · 虚拟终端").click();
  const dialog = page.getByRole("dialog");
  await dialog.waitFor({ timeout: 20000 });
  const tabs = await dialog.locator('[role="tab"]').allTextContents();
  ["虚拟终端", "文件管理", "系统信息"].every((t) => tabs.some((x) => x.includes(t)))
    ? ok("工作台三页签齐全")
    : bad("工作台三页签齐全", JSON.stringify(tabs));
  let term = await runCommand(page, "id");
  term.includes("uid=33") ? ok("PHP 终端回传 id 输出") : bad("PHP 终端回传 id 输出", flat(term));
  term.includes("POSIX") ? ok("系统族徽章为 POSIX") : bad("系统族徽章为 POSIX", flat(term.slice(0, 120)));
  // cwd 胶囊是 dialog 里唯一同时带 truncate 与 font-mono 的 span；「目标 x.x.x.x」
  // 那个 chip 也带 bg-muted，用类名单筛会拿错。
  const chip = await dialog.locator("span.truncate.font-mono").first().innerText();
  chip === "/var/www/html/assets"
    ? ok("首条命令后目录为 " + chip)
    : bad("首条命令后目录应为脚本目录", chip);
  await shot(page, "wb-02-php-terminal.png");

  // 3) stderr 与目录跳转
  term = await runCommand(page, "ls /definitely-not-here");
  term.includes("No such file") ? ok("PHP 终端回传 stderr") : bad("PHP 终端回传 stderr", flat(term.slice(-200)));
  const jump = dialog.getByPlaceholder(/粘贴目录后回车跳转/);
  await jump.fill("/etc");
  const beforeJump = await turnCount(page);
  await jump.press("Enter");
  await waitTurn(page, beforeJump);
  term = await dialog.innerText();
  term.includes("/etc") ? ok("目录跳转把会话目录切到 /etc") : bad("目录跳转把会话目录切到 /etc", flat(term.slice(0, 200)));

  // 4) 超时只停止本地等待
  term = await runCommand(page, "sleep 30", "15s 超时");
  term.includes("超时") ? ok("超时命令标为「超时」而不是失败") : bad("超时命令标为「超时」", flat(term.slice(-260)));
  await shot(page, "wb-03-php-timeout.png");

  // 5) 文件管理（大马）
  await dialog.getByRole("tab", { name: "文件管理" }).click();
  await waitForDialogText(page, /tpl-render\.php/);
  await shot(page, "wb-04-php-files.png");
  ok("大马列出网站目录文件");

  // 6) 系统信息：命令通道分区 + PHP 运行时自述
  await dialog.getByRole("tab", { name: "系统信息" }).click();
  await waitForDialogText(page, /主机与系统/, 130000);
  const info = await dialog.innerText();
  info.includes("PHP") && info.includes("8.1")
    ? ok("PHP 运行时自述合并展示")
    : bad("PHP 运行时自述合并展示", flat(info));
  info.includes("disable_functions") ? ok("运行时包含 disable_functions 行") : bad("运行时 disable_functions", flat(info));
  await shot(page, "wb-05-php-info.png");
  await page.keyboard.press("Escape");
  await page.waitForTimeout(1000);

  // 7) JSP 壳：同一组件走 Tomcat 通道
  await jspRow.getByTitle("工作台 · 虚拟终端").click();
  const dlg2 = page.getByRole("dialog");
  await dlg2.waitFor({ timeout: 20000 });
  const jspTerm = await runCommand(page, "uname -a; id; pwd");
  jspTerm.includes("Linux") && jspTerm.includes("uid=999(tomcat)")
    ? ok("JSP 终端回传 uname/id")
    : bad("JSP 终端回传 uname/id", flat(jspTerm));
  await shot(page, "wb-06-jsp-terminal.png");

  await dlg2.getByRole("tab", { name: "文件管理" }).click();
  await waitForDialogText(page, /report-view\.jsp/);
  ok("JSP 大马列出自身载荷");
  await shot(page, "wb-07-jsp-files.png");

  await dlg2.getByRole("tab", { name: "系统信息" }).click();
  await waitForDialogText(page, /提权线索/, 130000);
  const jspInfo = await dlg2.innerText();
  jspInfo.includes("只有 PHP v2 壳能回答")
    ? ok("JSP 缺少运行时自述有解释")
    : bad("JSP 缺少运行时自述有解释", flat(jspInfo));
  await shot(page, "wb-08-jsp-info.png");

  // A5：非 v2 壳的「文件管理」是禁用的，但禁用本身不说明原因，看着像功能坏了。
  const apiCall = (method, p, body) =>
    fetch(BASE + p, {
      method,
      headers: { Cookie: `jingwei_token=${token}`, "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    }).then((r) => r.json());
  const created = await apiCall("POST", "/api/deep/webshells", {
    name: "A5 旧协议提示验证",
    url: "http://172.23.0.1:8080/assets/legacy-hint.php",
    shell_type: "php",
    protocol: "legacy",
    password: "LegacyHint-2026-pw",
    source: "manual",
    note: "临时夹具：验证禁用页签的说明",
  });
  const legacyID = created.id || (created.webshell && created.webshell.id);
  if (!legacyID) {
    bad("创建旧协议壳夹具", JSON.stringify(created).slice(0, 140));
  } else {
    await page.goto(BASE + "/function/deep/webshells", { waitUntil: "networkidle", timeout: 60000 });
    await page.waitForTimeout(2500);
    const legacyRow = page.locator("tr", { hasText: "legacy-hint.php" });
    await legacyRow.getByTitle("工作台 · 虚拟终端").click();
    const dlg3 = page.getByRole("dialog");
    await dlg3.waitFor({ timeout: 20000 });
    const hintText = await dlg3.innerText();
    hintText.includes("文件管理（大马）走加密 v2")
      ? ok("旧协议壳说明了文件管理为何不可用")
      : bad("旧协议壳的禁用说明", flat(hintText));
    hintText.includes("明文") ? ok("旧协议壳的协议徽章写「明文」") : bad("旧协议壳协议徽章", flat(hintText.slice(0, 200)));
    await shot(page, "wb-09-legacy-hint.png");
    await page.keyboard.press("Escape");
    await page.waitForTimeout(800);
    await apiCall("DELETE", "/api/deep/webshells/" + legacyID);
    ok("旧协议壳夹具已删除");
  }

  errors.length === 0 ? ok("无页面 JS 错误") : bad("无页面 JS 错误", errors.join(" | ").slice(0, 300));
  console.log("\nPASS=" + PASS.length + " FAIL=" + FAIL.length);
  if (FAIL.length) console.log("FAILURES:\n- " + FAIL.join("\n- "));
  await browser.close();
})().catch((e) => {
  console.log("SCRIPT ERROR: " + e.message);
  console.log("PASS=" + PASS.length + " FAIL=" + FAIL.length);
  if (FAIL.length) console.log("FAILURES:\n- " + FAIL.join("\n- "));
  process.exit(1);
});
