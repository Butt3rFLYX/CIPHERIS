// Browser test of the CIPHERIS interface.
//
//   cargo build --release
//   npm install --no-save playwright@1 && npx playwright install chromium
//   node tools/e2e/ui.test.mjs target/release/cipheris [screenshot dir] [large png]
//
// Starts the app without opening a browser, drives it with Chromium and
// fails with a non zero exit code on the first broken expectation.

import { spawn } from "node:child_process";
import { mkdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const { chromium } = createRequire(import.meta.url)("playwright");

const here = dirname(fileURLToPath(import.meta.url));
const bin = process.argv[2] || "target/release/cipheris";
const shots = process.argv[3] || "";
const bigPng = process.argv[4] || "";
const photo = join(here, "fixtures", "photo.jpg");
const legacyPng = join(here, "..", "..", "crates", "stego", "tests", "fixtures", "sss_v1.png");
const legacyKey = readFileSync(join(here, "..", "..", "crates", "stego", "tests", "fixtures", "sss_v1.key"), "utf8");
if (shots) mkdirSync(shots, { recursive: true });

let failures = 0;
function check(cond, what) {
  console.log(`${cond ? "ok  " : "FAIL"} ${what}`);
  if (!cond) failures++;
}

const args = ["--no-browser"];
if (process.getuid && process.getuid() === 0) args.push("--allow-root");
const app = spawn(bin, args, { stdio: ["ignore", "pipe", "inherit"] });
let appExited = false;
app.on("exit", () => (appExited = true));
const url = await new Promise((resolve, reject) => {
  let out = "";
  app.stdout.on("data", (d) => {
    out += d;
    const m = /(http:\/\/127\.0\.0\.1:\d+\/launch\/[0-9a-f]{64})/.exec(out);
    if (m) resolve(m[1]);
  });
  app.on("exit", () => reject(new Error("app exited early")));
  setTimeout(() => reject(new Error("no launch URL")), 10000);
});
const origin = new URL(url).origin;

const browser = await chromium.launch();
const ctx = await browser.newContext({ acceptDownloads: true, viewport: { width: 1000, height: 900 }, locale: "en-US" });
const page = await ctx.newPage();
const consoleErrors = [];
page.on("pageerror", (e) => consoleErrors.push(String(e)));
page.on("console", (m) => {
  if (m.type() === "error" && !/status of (4\d\d)/.test(m.text())) consoleErrors.push(m.text());
});

// Launch and session
await page.goto(url);
await page.waitForFunction(() => document.getElementById("status-idle").textContent.length > 0);
check(page.url() === origin + "/", "launch link redirects to the interface");
check((await page.textContent("#hide-limits")).includes("100 MB"), "maximum file size shown");
const privacy = await page.evaluate(() => ({
  translate: document.documentElement.getAttribute("translate"),
  google: document.querySelector('meta[name="google"]')?.content,
  spell: [...document.querySelectorAll("textarea, input:not([type=file])")].every((e) => e.spellcheck === false),
  grammar: document.getElementById("hide-text").dataset.gramm === "false",
  manager: document.getElementById("reveal-key").dataset["1pIgnore"] === "true",
}));
check(privacy.translate === "no" && privacy.google === "notranslate", "page refuses machine translation (would send the message to a service)");
check(privacy.spell, "spell checking off in every text field (enhanced spell check sends text to a service)");
check(privacy.grammar && privacy.manager, "writing assistants and password managers told to ignore the fields");
const storage = await page.evaluate(() => [localStorage.length, sessionStorage.length, document.cookie]);
check(storage[0] === 0 && storage[1] === 0, "nothing stored in browser storage");
check(storage[2] === "", "session cookie is invisible to JavaScript");

const other = await (await browser.newContext()).newPage();
const second = await other.goto(url);
check(second.status() === 401 && (await other.textContent("body")).includes("Start CIPHERIS again"), "launch link cannot be used twice");
await page.reload();
await page.waitForFunction(() => document.getElementById("status-idle").textContent.length > 0);
check(await page.isHidden("#ended"), "reload keeps the session");

// Hide with a rotated JPEG
await page.setInputFiles("#hide-file", photo);
await page.waitForSelector("#hide-drop.filled");
const meta = await page.textContent("#hide-drop .meta");
check(meta.includes("1200 × 1600 px, converted to PNG"), "JPEG converted with orientation: " + meta.split("\n")[1]);
const message = "Meet me tomorrow at 7 pm at the old bridge. 🌉 Grüße, ñ, 日本";
await page.fill("#hide-text", message);
check((await page.textContent("#hide-meter .count")).startsWith(`${new TextEncoder().encode(message).length} /`), "byte counter");
if (shots) await page.screenshot({ path: join(shots, "hide-filled.png"), fullPage: true });
await page.click("#hide-go");
await page.waitForSelector("#hide-result:not([hidden])");
const rows = await page.$$eval("#hide-log .row", (r) => r.map((x) => x.textContent));
check(rows.length === 5 && rows.slice(1).every((r) => r.includes("ok")), "five log rows after hiding");
check(rows.some((r) => r.includes("metadata removed")), "metadata row present");
const key = (await page.textContent("#hide-key")).trim();
check(/^([0-9A-Z]{4} ){6}[0-9A-Z]{4}$/.test(key), "key shown in groups with spaces");
const [dl] = await Promise.all([page.waitForEvent("download"), page.click("#hide-save")]);
const saved = join(shots || "/tmp", "cipheris-e2e.png");
await dl.saveAs(saved);
check(dl.suggestedFilename() === "photo.png", "download name");
if (shots) await page.screenshot({ path: join(shots, "hide-done.png"), fullPage: true });

// Reveal: typo, wrong key, right key typed sloppily
await page.click("#tab-reveal");
await page.setInputFiles("#reveal-file", saved);
await page.waitForSelector("#reveal-drop.filled");
check((await page.getAttribute("#reveal-key", "type")) === "password", "key input masked by default");
const typo = key.slice(0, -1) + (key.endsWith("X") ? "Y" : "X");
await page.fill("#reveal-key", typo);
await page.click("#reveal-go");
await page.waitForSelector("#reveal-log .row.error");
check((await page.textContent("#reveal-log")).includes("typo"), "typo reported");
// A correctly formed key that belongs to a different image.
await page.fill("#reveal-key", legacyKey);
await page.click("#reveal-go");
await page.waitForFunction(() => document.querySelectorAll("#reveal-log .row.error").length === 2);
check((await page.textContent("#reveal-log")).includes("No message found"), "wrong key gives the generic message");
await page.fill("#reveal-key", key.toLowerCase().replace(/ /g, "-"));
await page.click("#reveal-show");
check((await page.getAttribute("#reveal-key", "type")) === "text", "show toggle reveals the key");
await page.click("#reveal-go");
await page.waitForSelector("#reveal-result:not([hidden])");
await page.waitForTimeout(200);
if (shots) await page.screenshot({ path: join(shots, "reveal-moment.png"), fullPage: true });
await page.waitForFunction((m) => document.getElementById("reveal-text").textContent === m, message, { timeout: 3000 });
check(true, "decrypted text matches after the animation");
check((await page.textContent("#reveal-text-sr")) === message, "screen reader text is final at once");
if (shots) await page.screenshot({ path: join(shots, "reveal-done.png"), fullPage: true });
await page.click("#reveal-clear");
check((await page.textContent("#reveal-text")) === "", "clear removes the plaintext");

// Legacy SSS image
await page.setInputFiles("#reveal-file", legacyPng);
await page.fill("#reveal-key", legacyKey);
await page.click("#reveal-go");
await page.waitForFunction(() => document.getElementById("reveal-text").textContent.startsWith("Legacy SSS message"), null, { timeout: 5000 });
check(true, "image from the old SSS release opens");

// A JPEG cannot carry a message
await page.setInputFiles("#reveal-file", photo);
await page.waitForFunction(() => document.getElementById("reveal-log").textContent.includes("exact PNG"), null, { timeout: 3000 })
  .then(() => check(true, "JPEG refused in reveal mode"), () => check(false, "JPEG refused in reveal mode"));

// Cancel a running operation
if (bigPng) {
  await page.click("#tab-hide");
  await page.click("#hide-new");
  await page.setInputFiles("#hide-file", bigPng);
  await page.waitForSelector("#hide-drop.filled", { timeout: 30000 });
  await page.fill("#hide-text", "cancel me");
  // Hold the answer back so there is time to press cancel.
  await page.route("**/api/hide", async (route) => {
    await new Promise((r) => setTimeout(r, 2000));
    await route.continue().catch(() => {});
  });
  await page.click("#hide-go");
  await page.waitForSelector("#hide-cancel:not([hidden])");
  await page.click("#hide-cancel");
  await page.waitForFunction(() => document.getElementById("hide-log").textContent.includes("cancelled"));
  check(await page.isHidden("#hide-result"), "cancel saves nothing");
  await page.unroute("**/api/hide");
}

// Reduced motion shows the plaintext immediately
const calm = await browser.newContext({ reducedMotion: "reduce" });
const cp = await calm.newPage();
await cp.goto(origin + "/");
check(await cp.isVisible("#ended"), "new browser profile without the cookie cannot use the session");

// Phone width
const phone = await ctx.newPage();
await phone.setViewportSize({ width: 390, height: 844 });
await phone.goto(origin + "/");
await phone.waitForFunction(() => document.getElementById("status-idle").textContent.length > 0);
await phone.setInputFiles("#hide-file", photo);
await phone.waitForSelector("#hide-drop.filled");
check(!(await phone.evaluate(() => document.documentElement.scrollWidth > innerWidth)), "no horizontal scrolling at 390 px");
if (shots) await phone.screenshot({ path: join(shots, "phone.png"), fullPage: true });

// Languages: switch by hand, server messages translated, system language detected
await phone.click('.langs button[data-lang="de"]');
check((await phone.textContent("#tab-hide")) === "verstecken" && (await phone.getAttribute("html", "lang")) === "de", "switch to German");
check((await phone.textContent("#hide-go .lbl")) === "nachricht verstecken", "German button label");
await phone.click("#tab-reveal");
await phone.setInputFiles("#reveal-file", legacyPng);
await phone.fill("#reveal-key", "0000 0000 0000 0000 0000 0000 0000");
await phone.click("#reveal-go");
await phone.waitForFunction(() => document.getElementById("reveal-log").textContent.includes("Tippfehler"), null, { timeout: 5000 })
  .then(() => check(true, "server error shown in German"), () => check(false, "server error shown in German"));
await phone.click('.langs button[data-lang="tr"]');
check((await phone.textContent("#tab-hide")) === "gizle" && (await phone.textContent("#reveal-go .lbl")) === "mesajı çöz", "switch to Turkish");
await phone.click('.langs button[data-lang="en"]');
check((await phone.textContent("#tab-hide")) === "hide", "switch back to English");
for (const [locale, word] of [["de-DE", "verstecken"], ["tr-TR", "gizle"], ["fr-FR", "hide"]]) {
  const c = await browser.newContext({ locale });
  const p = await c.newPage();
  await p.goto(origin + "/");
  await p.waitForSelector("#ended:not([hidden])");
  check((await p.textContent("#tab-hide")) === word, `system language ${locale} gives "${word}"`);
  await c.close();
}

// Security headers as the browser sees them
const res = await page.request.get(origin + "/");
check(res.headers()["content-security-policy"].includes("script-src 'self'"), "CSP present");
const cross = await page.request.post(origin + "/api/status", { headers: { Origin: "http://evil.example", "X-Cipheris": "1" } });
check(cross.status() === 403, "foreign origin refused");

check(consoleErrors.length === 0, "no script errors" + (consoleErrors.length ? ": " + consoleErrors.join(" | ") : ""));

// Quit
await page.click("#tab-hide");
await page.click("#quit");
await page.waitForSelector(".stopped");
for (let i = 0; i < 30 && !appExited; i++) await new Promise((r) => setTimeout(r, 100));
const exited = appExited;
check(exited, "quit stops the app");

await browser.close();
if (!exited) app.kill();
console.log(failures ? `\n${failures} check(s) failed` : "\nall checks passed");
process.exit(failures ? 1 : 0);
