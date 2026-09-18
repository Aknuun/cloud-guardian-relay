// ============================================================
// srv-relay — رلهٔ واحد نگهبان ابری برای SSH
// همهٔ قابلیت‌هایی که کلادفلر ورکر مستقیم نمی‌تواند انجام دهد
// از این رله عبور می‌کنند (کلادفلر به پورت 22 از طریق connect()
// دسترسی ندارد؛ پورت‌های بالا آزاد هستند):
//   • /exec  → اجرای یک دستور SSH (با رمز یا کلید) — SSH اینلاین داخل چت
//   • /install-node → نصب خودکار نود پاسارگارد (pg-node.sh) روی سرور مقصد
//   • /stats → مانیتور سرور: CPU / RAM / دیسک / uptime / پهنای باند
//   • /ping  → health-check رله
//
// نصب: sudo bash srv-relay-install.sh   (systemd + فایروال)
// احراز: هدر X-SRV-Token باید با SRV_RELAY_TOKEN برابر باشد.
// امنیت: هیچ رمزی ذخیره نمی‌شود؛ فقط در حافظهٔ همان درخواست استفاده می‌شود.
// ============================================================
const http = require("http");
const { execFile, spawn } = require("child_process");
const os = require("os");

const PORT = Number(process.env.SRV_RELAY_PORT || 8788);
const TOKEN = process.env.SRV_RELAY_TOKEN || "";

// محدودیت‌ها
const EXEC_TIMEOUT_MS = Number(process.env.SRV_EXEC_TIMEOUT_MS || 45000);
// سقف تایم‌اوت per-request — کمتر از محدودیت ~۱۰ دقیقه‌ای کلادفلر
const EXEC_MAX_MS = Number(process.env.SRV_EXEC_MAX_MS || 570000);
const INSTALL_TIMEOUT_MS = Number(process.env.SRV_INSTALL_TIMEOUT_MS || 480000);
const STATS_TIMEOUT_MS = Number(process.env.SRV_STATS_TIMEOUT_MS || 25000);
const MAX_SESSIONS_PER_MIN = 20;

// rate-limit ساده در حافظه
const _hits = [];
function rateOk() {
  const now = Date.now();
  while (_hits.length && now - _hits[0] > 60000) _hits.shift();
  if (_hits.length >= MAX_SESSIONS_PER_MIN) return false;
  _hits.push(now);
  return true;
}

function json(res, statusCode, obj) {
  const b = Buffer.from(JSON.stringify(obj));
  res.writeHead(statusCode, { "content-type": "application/json; charset=utf-8", "content-length": b.length });
  res.end(b);
}

function readBody(req, limit = 512 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > limit) {
        reject(new Error("body_too_large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

// --- ساخت فایل موقت اعتبارنامهٔ SSH با دسترسی سخت‌گیرانه ---
const fs = require("fs");
const path = require("path");

async function writeAuthFiles(auth) {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "srva-"));
  await fs.promises.chmod(dir, 0o700);
  const files = { dir, keyPath: null, passPath: null };
  if (auth.key) {
    const kp = path.join(dir, "id_key");
    let keyText = String(auth.key).replace(/\r\n/g, "\n");
    if (!keyText.endsWith("\n")) keyText += "\n";
    await fs.promises.writeFile(kp, keyText, { mode: 0o600 });
    await fs.promises.chmod(kp, 0o600);
    files.keyPath = kp;
    if (auth.keyPass) {
      const pp = path.join(dir, "keypass");
      await fs.promises.writeFile(pp, String(auth.keyPass) + "\n", { mode: 0o600 });
      files.passPath = pp;
    }
  } else if (auth.password) {
    const pp = path.join(dir, "pass");
    await fs.promises.writeFile(pp, String(auth.password) + "\n", { mode: 0o600 });
    files.passPath = pp;
  }
  return files;
}

async function cleanupAuthFiles(files) {
  if (!files || !files.dir) return;
  try {
    await fs.promises.rm(files.dir, { recursive: true, force: true });
  } catch (e) {}
}

// --- ساخت آرگومان‌های ssh برای یک اتصال ---
// نکته: BatchMode عمداً گذاشته نمی‌شود؛ با sshpass و askpass ناسازگار است (پرامپت رمز را کور می‌کند).
function sshArgs(host, port, user, files, extraArgs = []) {
  const args = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "ConnectTimeout=12",
    "-o", "LogLevel=ERROR",
    "-p", String(Number(port) || 22),
  ];
  if (files.keyPath) args.push("-i", files.keyPath);
  args.push(`${user || "root"}@${host}`);
  args.push(...extraArgs);
  return args;
}

// اجرای یک پروسه (ssh یا sshpass) با گرفتن stdout/stderr و timeout
function runProc(bin, args, env, timeoutMs, onStdout) {
  return new Promise((resolve) => {
    const child = spawn(bin, args, {
      env: { ...env, PATH: process.env.PATH },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    let err = "";
    let done = false;
    const timer = setTimeout(() => {
      if (!done) {
        done = true;
        try { child.kill("SIGKILL"); } catch (e) {}
        resolve({ code: 124, out, err: err + "\n⏱ مهلت اجرا به پایان رسید.", timedOut: true });
      }
    }, timeoutMs);
    child.stdout.on("data", (d) => {
      if (out.length < 900000) out += d.toString();
      if (onStdout) { try { onStdout(d.toString()); } catch (e) {} }
    });
    child.stderr.on("data", (d) => {
      if (err.length < 100000) err += d.toString();
    });
    child.on("error", (e) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve({ code: -1, out, err: String(e) });
    });
    child.on("close", (code) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve({ code: code === null ? -1 : code, out, err, timedOut: false });
    });
  });
}

// اعتبارنامهٔ رمزی: با sshpass اجرا می‌کنیم (در صورت نصب)
async function sshExec(host, port, user, auth, command, timeoutMs, onStdout) {
  if (!host || !/^[A-Za-z0-9._:-]+$/.test(host)) return { code: -1, err: "invalid_host" };
  const portNum = Number(port) || 22;
  if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) return { code: -1, err: "invalid_port" };
  if (!command) return { code: -1, err: "no_command" };

  const files = await writeAuthFiles(auth);
  try {
    let env = { ...process.env };
    let bin = "ssh";
    if (files.keyPath) {
      // کلید: اگر passphrase دارد از طریق اسکریپت askpass (در env) پاس می‌شود
      if (files.passPath) {
        const askpass = path.join(files.dir, "askpass.sh");
        await fs.promises.writeFile(askpass, `#!/bin/sh\ncat "${files.passPath}"\n`, { mode: 0o700 });
        env = { ...env, SSH_ASKPASS: askpass, SSH_ASKPASS_REQUIRE: "force", DISPLAY: ":0" };
      }
      args = sshArgs(host, portNum, user, files);
    } else if (files.passPath) {
      // رمز عبور: sshpass (اگر نصب نبود خطای روشن می‌دهیم)
      // ⚠️ آرگومان‌های sshpass فقط برای باینری sshpass است — به ssh داده نمی‌شود.
      const hasSshpass = await new Promise((r) => execFile("which", ["sshpass"], (e) => r(!e)));
      if (!hasSshpass) return { code: -1, err: "sshpass_not_installed_on_relay" };
      bin = "sshpass";
      args = ["-f", files.passPath, "ssh", ...sshArgs(host, portNum, user, files)];
    } else {
      return { code: -1, err: "no_auth" };
    }
    args.push(command);
    const r = await runProc(bin, args, env, timeoutMs, onStdout);
    return r;
  } finally {
    await cleanupAuthFiles(files);
  }
}

// --- جمع‌کردن آمار منابع از سرور مقصد ---
async function sshStats(host, port, user, auth) {
  const script = [
    "echo '===SYS==='",
    "hostname",
    "echo '===CPU==='",
    "top -bn1 | grep 'Cpu(s)' | awk '{print int($2+$4)}'",
    "echo '===CORES==='",
    "nproc",
    "echo '===MEM==='",
    "free -m | awk '/Mem:/{printf \"%d %d %d\", $2, $3, $7}'",
    "echo '===SWAP==='",
    "free -m | awk '/Swap:/{printf \"%d %d\", $2, $3; exit}'",
    "echo '===DISK==='",
    "df -h / | awk 'NR==2{printf \"%s %s %s %s\", $2, $3, $4, $5}'",
    "echo '===LOAD==='",
    "cat /proc/loadavg | awk '{print $1, $2, $3}'",
    "echo '===UPTIME==='",
    "awk '{printf \"%.0f\", $1}' /proc/uptime",
    "echo '===NET==='",
    "cat /proc/net/dev | awk 'NR>2 && $1!~/lo:/ {gsub(\":\",\"\",$1); print $1, $2, $10}'",
    "echo '===PG==='",
    "docker ps --format '{{.Names}}|{{.Status}}' 2>/dev/null || true",
    "echo '===END==='",
  ].join("; ");
  const r = await sshExec(host, port, user, auth, script, STATS_TIMEOUT_MS);
  if (r.code !== 0 && !r.out) return { error: r.err || `ssh_exit_${r.code}` };
  // تجزیه
  const pick = (tag) => {
    const m = r.out.match(new RegExp(`===${tag}===\\n([^=]*?)\\n`));
    return m ? m[1].trim() : "";
  };
  const sys = pick("SYS");
  const cpuPct = parseInt(pick("CPU"), 10) || 0;
  const cores = parseInt(pick("CORES"), 10) || 1;
  const memParts = pick("MEM").split(/\s+/).map(Number);
  const swapParts = pick("SWAP").split(/\s+/).map(Number);
  const diskParts = pick("DISK").split(/\s+/);
  const load = pick("LOAD").split(/\s+/).map(Number);
  const uptimeS = parseInt(pick("UPTIME"), 10) || 0;
  const netLines = (r.out.split("===NET===\n")[1] || "").split("===PG===")[0].trim().split("\n").filter(Boolean);
  const net = [];
  for (const l of netLines) {
    const p = l.trim().split(/\s+/);
    if (p.length >= 3) net.push({ iface: p[0], rx: Number(p[1]) || 0, tx: Number(p[2]) || 0 });
  }
  const pg = (r.out.split("===PG===\n")[1] || "").split("===END===")[0].trim().split("\n").filter((x) => x && x.includes("|"));
  return {
    host, sys,
    cpu: { pct: cpuPct, cores, load: load[0] ?? 0 },
    mem: { totalMb: memParts[0] || 0, usedMb: memParts[1] || 0, availMb: memParts[2] || 0 },
    swap: { totalMb: swapParts[0] || 0, usedMb: swapParts[1] || 0 },
    disk: { total: diskParts[0] || "?", used: diskParts[1] || "?", avail: diskParts[2] || "?", pct: diskParts[3] || "?" },
    uptimeS,
    net,
    pg,
    _raw: r.out.length,
  };
}

// --- نصب خودکار نود پاسارگارد ---
async function sshInstallNode(host, port, user, auth, onStdout) {
  const cmd =
    "export DEBIAN_FRONTEND=noninteractive; " +
    'sudo bash -c "$(curl -sL https://github.com/PasarGuard/scripts/raw/main/pg-node.sh)" @ install -y 2>&1; ' +
    'echo "PG_NODE_EXIT_CODE=$?"';
  const r = await sshExec(host, port, user, auth, cmd, INSTALL_TIMEOUT_MS, onStdout);
  const ok = /PG_NODE_EXIT_CODE=0/.test(r.out);
  return { ...r, ok };
}

// ============================ HTTP ============================
const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const p = u.pathname.replace(/\/+$/, "") || "/";
  try {
    // health-check بدون توکن
    if (p === "/ping") return json(res, 200, { ok: true, service: "srv-relay", ts: Date.now() });

    // احراز هویت برای بقیهٔ مسیرها
    const token = req.headers["x-srv-token"] || u.searchParams.get("token") || "";
    if (!TOKEN || token !== TOKEN) return json(res, 403, { error: "forbidden" });

    if (!rateOk()) return json(res, 429, { error: "rate_limited" });

    if (req.method !== "POST") return json(res, 405, { error: "method" });

    let body = {};
    try {
      body = JSON.parse(await readBody(req));
    } catch (e) {
      return json(res, 400, { error: "bad_json" });
    }

    if (p === "/exec") {
      const { host, port, user, password, key, keyPass, command } = body;
      // تایم‌اوت per-request از ورکر (برای عملیات طولانی مثل apt upgrade)
      const reqTimeout = Number(body.timeoutMs) || EXEC_TIMEOUT_MS;
      const tMs = Math.min(Math.max(reqTimeout, 3000), EXEC_MAX_MS);
      const r = await sshExec(host, port, user, { password, key, keyPass }, String(command || "").slice(0, 20000), tMs);
      return json(res, 200, { code: r.code, out: String(r.out || "").slice(-60000), err: String(r.err || "").slice(-4000), timedOut: !!r.timedOut, timeoutMs: tMs });
    }

    if (p === "/stats") {
      const { host, port, user, password, key, keyPass } = body;
      const r = await sshStats(host, port, user, { password, key, keyPass });
      if (r.error) return json(res, 200, { error: r.error });
      return json(res, 200, r);
    }

    if (p === "/install-node") {
      const { host, port, user, password, key, keyPass } = body;
      res.writeHead(200, { "content-type": "application/x-ndjson; charset=utf-8" });
      let last = Date.now();
      const onChunk = (txt) => {
        // خروجی زنده به‌صورت NDJSON — هر خط یک رویداد
        const now = Date.now();
        if (now - last < 900) return; // نرخ ارسال را کنترل می‌کنیم
        last = now;
        try { res.write(JSON.stringify({ t: "out", d: txt.slice(-3000) }) + "\n"); } catch (e) {}
      };
      const r = await sshInstallNode(host, port, user, { password, key, keyPass }, onChunk);
      try { res.end(JSON.stringify({ t: "done", ok: r.ok, code: r.code, tail: String(r.out || "").slice(-8000), err: String(r.err || "").slice(-2000) }) + "\n"); } catch (e) {}
      return;
    }

    return json(res, 404, { error: "not_found" });
  } catch (e) {
    try { json(res, 500, { error: "internal", detail: String(e).slice(0, 300) }); } catch (x) {}
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`[srv-relay] listening on 0.0.0.0:${PORT}`);
  if (!TOKEN) console.warn("[srv-relay] ⚠️ SRV_RELAY_TOKEN خالی است — همهٔ درخواست‌ها رد می‌شوند.");
});
