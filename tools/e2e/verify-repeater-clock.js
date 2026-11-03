// 浏览器端到端验证「请求重发」页上方的时钟块：公历到秒、每秒走字、带边框、可鼠标左右拖拽、位置记住。
// 打的是运行中的实例，会话令牌从 JW_TOKEN_FILE 读（默认 /tmp/jw.token），只注入浏览器上下文，不打印。
const { chromium } = require("playwright");
const fs = require("fs");
const path = require("path");

const BASE = process.env.JW_BASE || "http://127.0.0.1:9790";
const OUT = process.env.JW_SHOTS || "shots";
const TOKEN_FILE = process.env.JW_TOKEN_FILE || "/tmp/jw.token";
const CLOCK_RE = /^\d{4}年\d{2}月\d{2}日 \d{2}:\d{2}:\d{2}$/;
const PREF = "jingwei.repeater.clock";

const PASS = [];
const FAIL = [];
const ok = (n) => {
  PASS.push(n);
  console.log("  OK   " + n);
};
const bad = (n, d) => {
  FAIL.push(n + " — " + d);
  console.log("  FAIL " + n + " — " + d);
};
const shot = (page, name) => page.screenshot({ path: path.join(OUT, name) });

/** 按住时钟块中心横向拖 dx 像素，返回拖完的位置。 */
async function dragBy(page, chip, dx) {
  const b = await chip.boundingBox();
  await page.mouse.move(b.x + b.width / 2, b.y + b.height / 2);
  await page.mouse.down();
  await page.mouse.move(b.x + b.width / 2 + dx, b.y + b.height / 2, { steps: 10 });
  await page.mouse.up();
  await page.waitForTimeout(120);
  return await chip.boundingBox();
}

(async () => {
  const token = fs.readFileSync(TOKEN_FILE, "utf8").trim();
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  await ctx.addCookies([{ name: "jingwei_token", value: token, url: BASE }]);
  const page = await ctx.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));

  await page.goto(`${BASE}/function/repeater/`, { waitUntil: "networkidle" });
  // 位置是偏好，会跨会话留着；先清掉再验默认值，否则「默认居中」在第二次跑必然假失败。
  await page.evaluate((k) => localStorage.removeItem(k), PREF);
  await page.reload({ waitUntil: "networkidle" });

  const clock = page.getByText(CLOCK_RE);
  try {
    await clock.waitFor({ timeout: 8000 });
    ok("时钟块出现在报文上方");
  } catch (e) {
    bad("时钟块出现在报文上方", "8 秒内没等到");
    await browser.close();
    return;
  }

  const rowBox = await page.locator("div.relative.flex.h-10").boundingBox();
  const rowRight = rowBox.x + rowBox.width;
  const box = await clock.boundingBox();

  const first = (await clock.textContent()).trim();
  ok("格式为 公历年月日 时分秒", CLOCK_RE.test(first), `拿到 ${first}`);

  await page.waitForTimeout(1300);
  const second = (await clock.textContent()).trim();
  ok("秒在走", second !== first, `${first} 与 ${second} 相同`);

  const reqHeader = await page.getByText("请求报文").first().boundingBox();
  ok("时钟在「请求报文」之上", box.y < reqHeader.y, `时钟 y=${box.y.toFixed(0)} 报文头 y=${reqHeader.y.toFixed(0)}`);

  const gridTop = await page.locator("div.mt-3.grid").boundingBox();
  ok(
    "请求/响应整体下移",
    gridTop.y - (rowBox.y + rowBox.height) >= 12,
    `间距 ${(gridTop.y - (rowBox.y + rowBox.height)).toFixed(0)}px`,
  );

  const border = await clock.evaluate((el) => getComputedStyle(el).borderWidth);
  ok("时钟整体被边框包住", parseFloat(border) > 0, `border-width=${border}`);

  const center = box.x + box.width / 2;
  ok(
    "默认居中",
    Math.abs(center - (rowBox.x + rowBox.width / 2)) < 8,
    `偏差 ${(center - (rowBox.x + rowBox.width / 2)).toFixed(0)}px`,
  );

  ok("没有左/中/右按钮", (await page.getByRole("button", { name: "中", exact: true }).count()) === 0, "按钮还在");
  ok("没有左右箭头按钮", (await page.locator('[title="往左挪"], [title="往右挪"]').count()) === 0, "按钮还在");

  const moved = await dragBy(page, clock, 180);
  ok("鼠标右拖 180px 生效", Math.abs(moved.x - box.x - 180) < 6, `实际移动 ${(moved.x - box.x).toFixed(0)}px`);
  await shot(page, "repeater-clock-dragged.png");

  const stored = await page.evaluate((k) => localStorage.getItem(k), PREF);
  const savedOffset = stored ? JSON.parse(stored).offset : null;
  ok("拖完把偏移写进 localStorage", Math.abs(savedOffset - 180) < 6, `存了 ${stored}`);

  const pushed = await dragBy(page, clock, 5000);
  ok(
    "往右拖过头会夹在行边缘内",
    pushed.x + pushed.width <= rowRight + 1,
    `右缘 ${Math.round(pushed.x + pushed.width)} > 行右 ${Math.round(rowRight)}`,
  );
  const pulled = await dragBy(page, clock, -10000);
  ok(
    "往左拖过头也夹在行内",
    pulled.x >= rowBox.x - 1,
    `左缘 ${Math.round(pulled.x)} < 行左 ${Math.round(rowBox.x)}`,
  );
  await shot(page, "repeater-clock-leftmost.png");

  await page.reload({ waitUntil: "networkidle" });
  await clock.waitFor({ timeout: 8000 });
  await page.waitForTimeout(300);
  const after = await clock.boundingBox();
  ok(
    "刷新后位置不变",
    Math.abs(after.x - pulled.x) < 6,
    `刷新后 x=${Math.round(after.x)}，拖完 x=${Math.round(pulled.x)}`,
  );

  const back = await dragBy(page, clock, 400);
  ok("刷新后还能继续拖", Math.abs(back.x - after.x - 400) < 8, `拖了 ${(back.x - after.x).toFixed(0)}px`);

  ok("无页面脚本报错", errors.length === 0, errors.slice(0, 2).join(" | "));

  await browser.close();
  console.log(`\nPASS=${PASS.length} FAIL=${FAIL.length}`);
  if (FAIL.length) {
    console.log(FAIL.map((f) => `  - ${f}`).join("\n"));
    process.exitCode = 1;
  }
})();
