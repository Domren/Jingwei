// 浏览器端到端验证「内网 SSH 会话终端复用了 webshell 那套虚拟终端」：
// 目标是真的 Ubuntu-1 sshd（172.23.0.1:2201，lab 账号），凭据口令在库里是密封的。
// 会话令牌从 /tmp/jw.token 读取，只注入浏览器上下文，不打印。
const { chromium } = require("playwright");
const fs = require("fs");
const path = require("path");

const BASE = process.env.JW_BASE || "http://127.0.0.1:9790";
const OUT = process.env.JW_SHOTS || "shots";
const SESSION = process.env.JW_SESSION_NAME || "Ubuntu-1 SSH 终端验证";
const PASS = [];
const FAIL = [];
const ok = (n) => { PASS.push(n); console.log("  OK   " + n); };
const bad = (n, d) => { FAIL.push(n + " — " + d); console.log("  FAIL " + n + " — " + d); };
const flat = (s) => s.replace(/\s+/g, " ").slice(0, 260);

const shot = (page, name) => page.screenshot({ path: path.join(OUT, name) });

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

  await page.goto(BASE + "/function/deep/intranet", { waitUntil: "networkidle", timeout: 60000 });
  await page.waitForTimeout(2500);
  const row = page.locator("tr", { hasText: SESSION });
  (await row.count()) === 1 ? ok("列表有 SSH 会话行") : bad("列表有 SSH 会话行", "行数=" + (await row.count()));
  const rowText = await row.innerText();
  rowText.includes("active") || rowText.includes("活跃") ? ok("会话状态活跃") : bad("会话状态活跃", flat(rowText));
  await shot(page, "it-01-sessions.png");

  await row.getByRole("button", { name: "终端" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.waitFor({ timeout: 20000 });
  const tabs = await dialog.locator('[role="tab"]').allTextContents();
  ["命令", "上传", "下载", "执行记录"].every((t) => tabs.some((x) => x.includes(t)))
    ? ok("会话对话框四页签齐全（含执行记录）")
    : bad("会话对话框四页签齐全", JSON.stringify(tabs));

  let term = await runCommand(page, "id; pwd");
  term.includes("uid=1000(lab)") ? ok("SSH 终端回传 id") : bad("SSH 终端回传 id", flat(term));
  term.includes("POSIX") ? ok("系统族徽章为 POSIX") : bad("系统族徽章为 POSIX", flat(term.slice(0, 120)));
  /exit\s*0/.test(term) ? ok("退出码徽章显示 exit 0") : bad("退出码徽章", flat(term.slice(-200)));
  await shot(page, "it-02-ssh-terminal.png");

  // A1：探测不到时可人工指定系统族，指定后快捷命令随之切换。
  const family = dialog.getByRole("combobox").first();
  const familyText = await family.innerText();
  familyText.includes("POSIX") ? ok("系统族选择器显示已探测到的 POSIX") : bad("系统族选择器", flat(familyText));
  await family.click();
  await page.getByRole("option", { name: "Windows cmd" }).click();
  (await page.getByRole("button", { name: "ipconfig /all" }).count()) > 0
    ? ok("切到 Windows cmd 后快捷命令随之更换")
    : bad("切到 Windows cmd 后快捷命令更换", "没找到 ipconfig /all");
  await family.click();
  await page.getByRole("option", { name: "自动探测系统族" }).click();
  term = await runCommand(page, "id");
  term.includes("uid=1000(lab)") ? ok("切回自动后仍能正常执行") : bad("切回自动后执行", flat(term.slice(-200)));

  term = await runCommand(page, "ls /definitely-not-here");
  term.includes("No such file") ? ok("SSH 终端回传 stderr") : bad("SSH 终端回传 stderr", flat(term.slice(-200)));
  /exit\s*2/.test(term) ? ok("非零退出码徽章 exit 2") : bad("非零退出码徽章", flat(term.slice(-200)));

  const jump = dialog.getByPlaceholder(/粘贴目录后回车跳转/);
  await jump.fill("/tmp");
  const beforeJump = await turnCount(page);
  await jump.press("Enter");
  await waitTurn(page, beforeJump);
  const chip = await dialog.locator("span.truncate.font-mono").first().innerText();
  chip === "/tmp" ? ok("跳转后当前目录为 /tmp") : bad("跳转后当前目录", chip);
  term = await runCommand(page, "pwd");
  term.includes("/tmp") ? ok("下一轮命令仍在 /tmp（cd 续用）") : bad("cd 续用", flat(term.slice(-200)));
  await shot(page, "it-03-ssh-cwd.png");

  term = await runCommand(page, "sleep 30", "15s 超时");
  term.includes("超时") ? ok("SSH 超时标为「超时」而不是失败") : bad("SSH 超时标记", flat(term.slice(-260)));
  await shot(page, "it-04-ssh-timeout.png");

  // A4：上传结果不再是把 note 拼进输出的一坨文本，而是同一套退出码/耗时/超时徽章。
  await dialog.getByRole("tab", { name: "上传" }).click();
  await dialog.locator('input[type="file"]').setInputFiles({
    name: "jw-upload-check.txt",
    mimeType: "text/plain",
    buffer: Buffer.from("jingwei upload check"),
  });
  await dialog.getByPlaceholder("/tmp/tool").fill("/tmp/jw-upload-check.txt");
  await dialog.getByRole("button", { name: "上传" }).last().click();
  await page.waitForFunction(
    () => {
      const el = document.querySelector('[role="dialog"]');
      return !!el && /exit\s*0/.test(el.innerText);
    },
    null,
    { timeout: 60000 }
  );
  const up = await dialog.innerText();
  up.includes("exit 0") ? ok("上传结果显示退出码徽章（与终端同一套）") : bad("上传结果徽章", flat(up.slice(-200)));
  await shot(page, "it-06-ssh-upload.png");
  // 命令页签没有常驻挂载，切回去才能继续用终端把上传的测试文件删掉。
  await dialog.getByRole("tab", { name: "命令" }).click();
  await runCommand(page, "rm -f /tmp/jw-upload-check.txt");

  await dialog.getByRole("tab", { name: "执行记录" }).click();
  await page.waitForTimeout(2500);
  const events = await dialog.innerText();
  events.includes("id; pwd") && events.includes("sleep 30")
    ? ok("执行记录切过去时重新读台账（含刚跑的命令）")
    : bad("执行记录刷新", flat(events));
  await shot(page, "it-05-ssh-events.png");

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
