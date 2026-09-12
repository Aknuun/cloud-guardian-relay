const BOT_TOKEN = "";
const ADMIN_ID = 172358305;

// ============================================================
// نسخهٔ ربات
// ⚠️ قانون: بعد از هر تغییر در این فایل، قبل از deploy مقدار
//    BOT_VERSION را یک واحد زیاد کن (مثلاً 8.1 → 8.2) و بعد deploy.
//    نسخه در منوی اصلی ربات نمایش داده می‌شود.
// ============================================================
const BOT_VERSION = "8.16";

const CF_API = "https://api.cloudflare.com/client/v4";
const ARVAN_API = "https://napi.arvancloud.ir/cdn/4.0";
const HETZNER_API = "https://api.hetzner.cloud/v1";
const LINODE_API = "https://api.linode.com/v4";
const RECORD_TYPES = ["A", "AAAA", "CNAME"];
const PAGE_SIZE = 8;
const RECORD_PAGE_SIZE = 18;
const CZ_PAGE_SIZE = 12;
const CZR_PAGE_SIZE = 16;
const HZ_PAGE_SIZE = 10;

const EMPTY_BTN = { text: "\u00A0", callback_data: "noop" };

let _lastSelfOrigin = "";

// ============================================================
// in-isolate micro cache — برای کاهش شدید مصرف Workers KV
// مقادیر پرخواندنی (کانفیگ/اکانت/پنل/کش) در حافظهٔ ایزوله نگه داشته
// می‌شوند و روی هر write باطل/به‌روز می‌شوند. TTL کوتاه = محافظت از
// دادهٔ کهنه در صورت نوشتن توسط ایزولهٔ دیگر.
// ============================================================
const _mem = new Map();
const MEM_TTL = 60000;

function memSet(key, val, ttl = MEM_TTL) {
  if (_mem.size > 800) _mem.clear();
  _mem.set(key, { v: val, exp: Date.now() + ttl });
}

function memGet(key) {
  const e = _mem.get(key);
  if (!e) return undefined;
  if (e.exp < Date.now()) {
    _mem.delete(key);
    return undefined;
  }
  return e.v;
}

function memDel(key) {
  _mem.delete(key);
}

async function kvGetCached(kv, key, type, ttl = MEM_TTL) {
  if (!kv) return null;
  const hit = memGet("kv:" + key);
  if (hit !== undefined) return hit;
  const val = await kv.get(key, type);
  if (val !== null && val !== undefined) memSet("kv:" + key, val, ttl);
  return val;
}

async function kvPutCached(kv, key, value, opts, ttl = MEM_TTL) {
  if (!kv) return;
  await kv.put(key, value, opts);
  try {
    memSet("kv:" + key, JSON.parse(value), ttl);
  } catch {
    memSet("kv:" + key, value, ttl);
  }
}

async function kvDeleteCached(kv, key) {
  if (!kv) return;
  memDel("kv:" + key);
  await kv.delete(key);
}

function grid2(buttons) {
  const rows = [];
  for (let i = 0; i < buttons.length; i += 2) {
    const row = [buttons[i]];
    row.push(buttons[i + 1] || EMPTY_BTN);
    rows.push(row);
  }
  return rows;
}

const SETTINGS_INFO = {
  ssl: { label: "حالت SSL", type: "enum", values: { off: "خاموش", flexible: "انعطاف‌پذیر", full: "کامل", strict: "کامل (سخت)" } },
  min_tls_version: { label: "حداقل نسخه TLS", type: "enum", values: { "1.0": "1.0", "1.1": "1.1", "1.2": "1.2", "1.3": "1.3" } },
  tls_1_3: { label: "TLS 1.3", type: "bool" },
  always_use_https: { label: "همیشه HTTPS", type: "bool" },
  automatic_https_rewrites: { label: "بازنویسی خودکار HTTPS", type: "bool" },
  security_level: { label: "سطح امنیت", type: "enum", values: { off: "خاموش", essentially_off: "خیلی کم", low: "کم", medium: "متوسط", high: "زیاد", under_attack: "حالت حمله" } },
  http2: { label: "HTTP/2", type: "bool" },
  http3: { label: "HTTP/3", type: "bool" },
  brotli: { label: "فشرده‌سازی Brotli", type: "bool" },
  ipv6: { label: "IPv6", type: "bool" },
  always_online: { label: "همیشه آنلاین", type: "bool" },
};

const SSL_KEYS = ["ssl", "min_tls_version", "tls_1_3", "always_use_https", "automatic_https_rewrites"];
const SEC_KEYS = ["security_level"];
const PERF_KEYS = ["http2", "http3", "brotli", "ipv6", "always_online"];

function groupKeysFor(setting) {
  if (SSL_KEYS.includes(setting)) return SSL_KEYS;
  if (SEC_KEYS.includes(setting)) return SEC_KEYS;
  return PERF_KEYS;
}

function groupTitleFor(setting) {
  if (SSL_KEYS.includes(setting)) return "🔒 SSL / TLS";
  if (SEC_KEYS.includes(setting)) return "🛡 امنیت";
  return "⚡ کارایی";
}

export default {
  async fetch(request, env, ctx) {
    const botToken = env.BOT_TOKEN || BOT_TOKEN;
    const adminId = Number(env.ADMIN_ID || ADMIN_ID);
    const kv = env.BOT_KV;
    const url = new URL(request.url);

    if (request.method === "POST" && (url.pathname.startsWith("/ndhook/") || url.pathname.startsWith("/node-hook/"))) {
      const parts = url.pathname.split("/").filter(Boolean);
      const token = parts[parts.length - 1] || "";
      let payload = {};
      try {
        payload = await request.json();
      } catch (e) {
        console.error("NDHOOK_PARSE", String(e));
      }
      ctx.waitUntil(handleNodeEvent(token, payload, env, botToken));
      return ok();
    }

    if (request.method !== "POST") return ok();

    let payload;
    try {
      payload = await request.json();
    } catch {
      return ok();
    }

    if (kv) ctx.waitUntil(cacheSelfUrl(kv, url.origin));

    ctx.waitUntil(processUpdate(payload, env, botToken, adminId));
    return ok();
  },

  async scheduled(event, env, ctx) {
    const cron = event.cron || "";
    if (cron === "0 9 * * *") {
      ctx.waitUntil(runSslMonitor(env));
    } else if (cron === "*/10 * * * *") {
      ctx.waitUntil(runNodePoll(env));
    } else if (cron === "* * * * *") {
      ctx.waitUntil(runReminders(env).catch((e) => console.error("REMIND", String(e))));
    } else {
      // host filter — روی هر کرون دیگری (مثلاً */5) اجرا می‌شود؛ لیمیت واقعی
      // با intervalMin داخل runHostFilter کنترل می‌شود.
      ctx.waitUntil(
        runHostFilter(env).catch(async (e) => {
          console.error("HOSTFILTER", e && e.stack ? e.stack : String(e));
          try {
            await env.BOT_KV.put("host_filter_crash", JSON.stringify({ ts: new Date().toISOString(), err: String(e && e.stack ? e.stack : e).slice(0, 900) }));
          } catch (x) {}
        })
      );
    }
  },
};

async function processUpdate(payload, env, botToken, adminId) {
  const kv = env.BOT_KV;

  try {
    if (payload.callback_query) {
      await handleCallback(payload.callback_query, botToken, adminId, kv, env);
      return;
    }

    if (!payload.message || !payload.message.text) return;

    const chatId = payload.message.chat.id;
    const admins = await getAdmins(kv, env);
    if (!admins.includes(chatId)) return;

    const send = async (msg, kb) => {
      if (msg && msg.indexOf(PERM_MARK) !== -1) {
        msg = msg.split(PERM_MARK).join("");
        try {
          await kv.put(`pretrytxt:${chatId}`, text, { expirationTtl: 900 });
        } catch (e) {}
        const rows = kb ? kb.slice() : [];
        rows.push([
          { text: "🔄 بررسی مجدد", callback_data: "permretrytxt" },
          { text: "⬅️ بازگشت", callback_data: "menu" },
        ]);
        kb = rows;
      }
      return sendMessage(botToken, chatId, msg, kb);
    };
    const text = payload.message.text.trim();

    if (!kv) {
      await send("⚠️ KV با نام BOT_KV لازم است.");
      return;
    }

    const accounts = await getAccounts(kv, env);
    const arvanAccounts = await getArvanAccounts(kv);
    const pending = await kv.get(`pend:${chatId}`, "json");

    if (pending && !text.startsWith("/")) {
      await resolvePending(pending, text, chatId, accounts, arvanAccounts, send, kv, botToken);
      return;
    }

    if (pending) await kv.delete(`pend:${chatId}`);

    const args = text.split(/\s+/);
    const cmd = args[0].toLowerCase();

    if (!text.startsWith("/") && (isIpLike(text) || isNameLike(text))) {
      const qa = await kv.get(`qa:${chatId}`, "json");
      if (isIpLike(text)) {
        await kv.put(`qa:${chatId}`, JSON.stringify({ ip: text.trim() }), { expirationTtl: 3600 });
        await sendQuickIpMenu(chatId, text.trim(), kv, accounts, send);
      } else {
        await quickNameSearch(text.trim(), qa && qa.ip ? qa : null, chatId, accounts, send, kv);
      }
      return;
    }

    if (cmd === "/start" || cmd === "/menu") {
      await send(mainMenuText(), mainMenuKeyboard());
    } else if (cmd === "/myid") {
      await send(`🆔 شناسه تلگرام شما: ${chatId}`);
    } else if (cmd === "/version") {
      await send(`🤖 نسخهٔ ربات: v${BOT_VERSION}`);
    } else if (cmd === "/help") {
      await send(helpText(), helpKeyboard());
    } else if (cmd === "/cancel") {
      await kv.delete(`qa:${chatId}`);
      await send("✅ عملیات جاری لغو شد.", mainMenuKeyboard());
    } else if (cmd === "/zones") {
      await showZones(0, "all", accounts, send, kv, chatId);
    } else if (cmd === "/records") {
      if (!args[1]) return showZones(0, "all", accounts, send, kv, chatId);
      const zone = await findZone(args[1], accounts);
      if (!zone) return send("❌ دامنه پیدا نشد.");
      await showRecords(zone, 0, accounts, send, kv);
    } else if (cmd === "/search") {
      await send("🔍 جستجوی رکورد\n\nبر اساس چه چیزی جستجو کنیم؟", [
        [{ text: "🔤 بر اساس نام/دامنه", callback_data: "sf:name" }],
        [{ text: "🌐 بر اساس IP/مقدار", callback_data: "sf:content" }],
        [{ text: "🏠 منو", callback_data: "menu" }],
      ]);
    } else if (cmd === "/add") {
      await handleAdd(args, accounts, send, kv);
    } else if (cmd === "/edit") {
      await handleEdit(args, accounts, send, kv);
    } else if (cmd === "/setttl") {
      await handleSetTtl(args, accounts, send, kv);
    } else if (cmd === "/toggleproxy") {
      await handleToggleProxy(args, accounts, send, kv);
    } else if (cmd === "/delete") {
      await handleDelete(args, accounts, send, kv);
    } else {
      await send("❓ دستور ناشناخته. از منو استفاده کنید.", mainMenuKeyboard());
    }
  } catch (err) {
    console.error("WORKER_ERROR", err && err.stack ? err.stack : String(err));
    try {
      await tg(botToken, "sendMessage", {
        chat_id: adminId,
        text: "❌ خطای داخلی:\n" + String(err && err.message ? err.message : err).substring(0, 3000),
      });
    } catch (e) {
      console.error("SEND_ERROR", String(e));
    }
  }
}

function ok() {
  return new Response("OK", { status: 200 });
}

function mainMenuText() {
  return `⚙️ تنظیمات v${BOT_VERSION}\n\n🏠 منوی اصلی\n\nیک گزینه را انتخاب کنید:`;
}

function mainMenuKeyboard() {
  return [
    [{ text: "🔍 جست و جو در همه", callback_data: "search", style: "danger" }],
    [{ text: "⭐ ساب‌های منتخب", callback_data: "favs" }, { text: "☁️ کلودفلر", callback_data: "zones" }],
    [{ text: "🏢 دیتاسنترها (هتزنر و ..)", callback_data: "providers" }],
    [
      { text: "🗂 عملیات گروهی", callback_data: "bulk_main", style: "plain" },
      { text: "➕ افزودن رکورد", callback_data: "addrec" },
    ],
    [{ text: "🖥 مانیتورها", callback_data: "mons" }],
    [{ text: "ℹ️ راهنما", callback_data: "help", style: "plain" }, { text: "👥 مدیریت ادمین", callback_data: "admins_menu" }],
  ];
}

function helpText() {
  return (
    "ℹ️ راهنما\n\n" +
    "یک بخش را انتخاب کن تا راهنمای همان بخش نمایش داده شود.\n" +
    "برای دیدن روش «جست‌وجوی سریع» با آی‌پی/ساب‌دامنه، دکمهٔ قرمز «⚡ جای‌گذاری سریع» را بزن.\n\n" +
    "💡 رنگ دکمه‌ها: قرمز = تک‌ستونه · آبی = دوستونه · سبز = سه‌ستونه"
  );
}

const HELP_GUIDE = {
  hqi:
    "⚡ جای‌گذاری سریع\n\n" +
    "در هر بخش از ربات (کلودفلر، آروان، رکوردها، مانیتورها و...) کافی است متن را در چت بفرستی؛ ربات خودش تشخیص می‌دهد و حالت «جست‌وجوی سریع» را فعال می‌کند:\n\n" +
    "• آی‌پی بفرستی → رکوردها و دامنه‌های مرتبط با همان آی‌پی جست‌وجو می‌شوند.\n" +
    "• ساب‌دامنه یا نام دامنه بفرستی → رکوردهای آن پیدا می‌شود و امکان ویرایش/تغییر مقدار، نوع و TTL فراهم است.\n\n" +
    "از داخل نتایج می‌توانی ساب‌دامنه را تغییر دهی، Proxy را روشن/خاموش کنی یا مقدار را در «⭐ ساب‌های منتخب» ذخیره کنی.",
  cf:
    "☁️ کلودفلر\n\n" +
    "• مشاهدهٔ دامنه‌ها به‌تفکیک اکانت و صفحه‌بندی\n" +
    "• افزودن دامنه جدید و افزودن اکانت کلودفلر (از دکمه‌های همان صفحه)\n" +
    "• ورود به هر دامنه: مشاهده/افزودن/ویرایش/حذف رکورد، تغییر TTL و Proxy\n" +
    "• تنظیمات دامنه (SSL و تنظیمات دیگر) و عملیات گروهی",
  arvan:
    "🇮🇷 آروان کلاد\n\n" +
    "دامنه را ابتدا از پنل آروان اضافه کن، سپس همین‌جا ساب‌دامنه/رکورد بساز و مدیریت کن.\n" +
    "برای دیدن دامنه‌های تازه، دکمهٔ «🔄 همگام‌سازی» را بزن. افزودن اکانت آروان هم از همان صفحه انجام می‌شود.",
  hz:
    "🏢 دیتاسنترها (هتزنر و لینود)\n\n" +
    "از منو → «🏢 دیتاسنترها» ارائه‌دهنده (هتزنر یا لینود) را انتخاب کن.\n" +
    "برای هر دو:\n" +
    "• سرورها: ساخت، روشن/خاموش/ری‌استارت/ریبوت، ریبیلد، ارتقا، ریست رمز، تغییر نام و حذف\n" +
    "• آی‌پی‌ها (افزودن/حذف/اختصاص) و رکورد PTR\n" +
    "• اسنپ‌شات‌ها: ساخت/تغییر نام/حذف",
  rec:
    "➕ افزودن رکورد\n\n" +
    "از منوی اصلی یا داخل هر دامنه، رکورد جدید را گام‌به‌گام بساز:\n" +
    "نوع (A/AAAA/CNAME) → نام/ساب‌دامنه → مقدار/آی‌پی → TTL → Proxy.",
  bulk:
    "🗂 عملیات گروهی\n\n" +
    "داخل هر دامنه دکمهٔ «🗂 گروهی» را بزن، چند ساب‌دامنه را انتخاب کن و یک‌جا:\n" +
    "• حذف کنی\n• مقدار را تغییر دهی\n• نوع رکورد را عوض کنی\n• به «⭐ ساب‌های منتخب» اضافه کنی",
  search:
    "🔍 جست‌وجو\n\n" +
    "جست‌وجوی رکورد در همهٔ اکانت‌ها بر اساس:\n" +
    "• نام/دامنه (بخشی از نام کافی است)\n" +
    "• آی‌پی یا بخشی از مقدار\n\n" +
    "همچنین هرجا در چت آی‌پی یا ساب‌دامنه بفرستی، جست‌وجوی سریع فعال می‌شود.",
  fav:
    "⭐ ساب‌های منتخب\n\n" +
    "آی‌پی/ساب‌های پرتکرارت را ذخیره کن تا بعداً سریع پیدا و جای‌گذاری کنی.\n" +
    "برای افزودن: داخل رکوردهای یک دامنه → «🗂 گروهی» → انتخاب → «⭐ افزودن به منتخب‌ها».",
  mons:
    "🖥 مانیتورها\n\n" +
    "• 🧭 مانیتور فیلتر شدن ساب: دامنه‌های هاست‌های پاسارگارد را دوره‌ای از داخل ایران بررسی می‌کند و در صورت فیلتر، دامنهٔ شماره‌دار جدید می‌سازد و جایگزین می‌کند.\n" +
    "• 🖥 مانیتور نود پاسارگارد: هشدار قطع/وصل شدن نودهای پنل (رویدادی/وبهوک) + همگام‌سازی دستی.\n" +
    "• 🔐 مانیتور SSL هم داخل همین بخش است.",
  ssl:
    "🔐 مانیتور SSL\n\n" +
    "دامنه‌ها را برای نظارت اضافه کن تا هنگام نزدیک‌شدن به انقضای گواهی (پیش‌فرض ۵ روز قبل) هشدار بگیری.",
  admin:
    "👥 مدیریت ادمین\n\n" +
    "افزودن/حذف ادمین (فقط ادمین اصلی). ادمین‌ها به همهٔ امکانات ربات دسترسی دارند.\n" +
    "شناسهٔ عددی را می‌توانی با /myid در ربات ببینی.",
};

function helpGuideKb() {
  return [
    [
      { text: "🔙 راهنمای بخش‌ها", callback_data: "help" },
      { text: "🏠 منو", callback_data: "menu" },
    ],
  ];
}

function helpKeyboard() {
  return [
    [{ text: "⚡ جای‌گذاری سریع", callback_data: "hqi", style: "danger" }],
    [
      { text: "🇮🇷 آروان", callback_data: "hg:arvan" },
      { text: "☁️ کلودفلر", callback_data: "hg:cf" },
    ],
    [
      { text: "🏢 دیتاسنترها", callback_data: "hg:hz" },
      { text: "🖥 مانیتورها", callback_data: "hg:mons" },
    ],
    [
      { text: "🗂 گروهی", callback_data: "hg:bulk" },
      { text: "➕ رکورد", callback_data: "hg:rec" },
      { text: "🔍 جست‌وجو", callback_data: "hg:search" },
    ],
    [
      { text: "🔐 مانیتور SSL", callback_data: "hg:ssl" },
      { text: "👥 ادمین", callback_data: "hg:admin" },
    ],
    [{ text: "⭐ ساب‌های منتخب", callback_data: "hg:fav" }],
    [{ text: "🏠 منو", callback_data: "menu" }],
  ];
}

function parseAccounts(env) {
  const raw = env.CF_ACCOUNTS || "[]";
  try {
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr.filter((a) => a && a.token) : [];
  } catch {
    return [];
  }
}

async function getAccounts(kv, env) {
  let list = await kvGetCached(kv, "accounts", "json");
  if (!Array.isArray(list)) {
    list = parseAccounts(env);
    if (list.length) await kvPutCached(kv, "accounts", JSON.stringify(list));
  }
  return list || [];
}

async function getAdmins(kv, env) {
  const main = Number(env.ADMIN_ID || ADMIN_ID);
  let list = await kvGetCached(kv, "admins", "json");
  if (!Array.isArray(list)) list = [];
  const set = new Set([main, ...list.map(Number)]);
  return [...set];
}

async function getAccountId(accounts, i) {
  const res = await fetch(`${CF_API}/zones?per_page=1`, { headers: hdr(accounts[i].token), signal: withTimeout() });
  const data = await res.json();
  if (data.success && data.result && data.result.length) return data.result[0].account.id;
  return null;
}

function hdr(token) {
  return { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
}

function withTimeout(ms) {
  try {
    return AbortSignal.timeout(ms || 15000);
  } catch {
    return undefined;
  }
}

// رنگ‌بندی دکمه‌ها:
//   • ردیف‌های «خطرناک» (حذف/لغو/بازگشت/توقف/غیرفعال/ریست/انصراف و...) → قرمز
//   • بقیه بر اساس تعداد دکمه در ردیف: ۱ و ۳ ستون → سبز · ۲ و ۴+ ستون → آبی
//   • ردیف‌های «لیست داده» (دامنه/ساب‌دامنه/رکورد/آی‌پی/سرور و...) بدون رنگ
//   • هر دکمه می‌تواند با style صریح رنگ ثابت بگیرد یا با {"style":"plain"} بی‌رنگ بماند.
const DATA_CB = /^(z:|zf:|e:|p:|sel:|selp:|dd:|arv:|arvpage:|sr:|zsf:|ap:|cz:|ndi:|ndip:|ndx:|pnd:|favopen:|favpk:|favpsel:|favpp:|hzsi:|hzpi:|hzni:|hzm:|hzs:|hzp:|hzn:|rempick:|rempage:|remdelx:)/;
const DANGER_CB = /(^|[:_])(del|delete|dacc|daccy|darvan|darvany|pnlx|nddel|nddely|sslmdy|hzd|hzdy|bulkdel|stop|suspend|cancel|revoke|reset)([:_]|$)/;

function isPlaceholderBtn(b) {
  return !b || typeof b !== "object" || b.text === "\u00A0";
}
function stripPlain(b) {
  if (b && typeof b === "object" && b.style === "plain") {
    const { style, ...rest } = b;
    return rest;
  }
  return b;
}
function rowIsData(row) {
  return row.some((b) => b && typeof b === "object" && DATA_CB.test(String(b.callback_data || "")));
}
function rowIsDanger(row) {
  return row.some((b) => {
    if (!b || typeof b !== "object") return false;
    if (b.style === "danger") return true;
    const cb = String(b.callback_data || "");
    const t = String(b.text || "");
    return (
      DANGER_CB.test(cb) ||
      /🗑|🛑|🚫/.test(t) ||
      /حذف|لغو|انصراف|غیرفعال|توقف|ریست|بازنشانی|پاک‌کردن|بازگشت/.test(t)
    );
  });
}
function autoStyleFor(row) {
  const n = row.filter((b) => !isPlaceholderBtn(b)).length;
  // ۱ و ۳ ستون → سبز · ۲ و ۴+ ستون → آبی
  return n === 2 || n >= 4 ? "primary" : "success";
}
function styleRow(row) {
  if (!Array.isArray(row)) return row;
  if (rowIsData(row)) return row.map(stripPlain);
  const auto = autoStyleFor(row);
  return row.map((b) => {
    if (isPlaceholderBtn(b)) return b;
    if (b.style === "plain") {
      const { style, ...rest } = b;
      return rest;
    }
    if (b.style) return b;
    return { ...b, style: auto };
  });
}
function applyBtnStyles(body) {
  const ik = body && body.reply_markup && body.reply_markup.inline_keyboard;
  if (!Array.isArray(ik)) return;
  body.reply_markup.inline_keyboard = ik.map(styleRow);
}

async function tg(botToken, method, body) {
  try {
    applyBtnStyles(body);
  } catch (e) {}
  const res = await fetch(`https://api.telegram.org/bot${botToken}/${method}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: withTimeout(30000),
  });
  return res.json();
}

async function sendMessage(botToken, chatId, text, keyboard) {
  const t = text.substring(0, 4000);
  const body = { chat_id: chatId, text: t };
  if (keyboard) body.reply_markup = { inline_keyboard: keyboard };
  if (t.includes("<code>")) body.parse_mode = "HTML";
  return tg(botToken, "sendMessage", body);
}

async function editMessage(botToken, chatId, messageId, text, keyboard) {
  const t = text.substring(0, 4000);
  const body = {
    chat_id: chatId,
    message_id: messageId,
    text: t,
  };
  if (keyboard) body.reply_markup = { inline_keyboard: keyboard };
  if (t.includes("<code>")) body.parse_mode = "HTML";
  return tg(botToken, "editMessageText", body);
}

async function getAllZones(accounts, kv) {
  if (kv) {
    const cached = await kvGetCached(kv, "cache:zones", "json", 3600000);
    if (Array.isArray(cached)) return cached;
  }
  const out = [];
  for (let i = 0; i < accounts.length; i++) {
    const acc = accounts[i];
    let page = 1;
    while (true) {
      const res = await fetch(`${CF_API}/zones?per_page=50&page=${page}`, { headers: hdr(acc.token), signal: withTimeout() });
      const data = await res.json();
      if (!data.success || !data.result || data.result.length === 0) break;
      for (const z of data.result) out.push({ ...z, _acc: i, _accName: acc.name });
      if (data.result.length < 50) break;
      page++;
    }
  }
  if (kv && out.length) await kvPutCached(kv, "cache:zones", JSON.stringify(out), { expirationTtl: 3600 }, 3600000);
  return out;
}

async function findZone(zoneName, accounts) {
  if (!zoneName) return null;
  for (let i = 0; i < accounts.length; i++) {
    const res = await fetch(`${CF_API}/zones?name=${encodeURIComponent(zoneName)}`, { headers: hdr(accounts[i].token), signal: withTimeout() });
    const data = await res.json();
    if (data.success && data.result && data.result.length > 0) {
      return { ...data.result[0], _acc: i, _accName: accounts[i].name };
    }
  }
  return null;
}

async function getZoneById(zoneId, accIndex, accounts) {
  const res = await fetch(`${CF_API}/zones/${zoneId}`, { headers: hdr(accounts[accIndex].token), signal: withTimeout() });
  const data = await res.json();
  return data.success ? { ...data.result, _acc: accIndex, _accName: accounts[accIndex].name } : null;
}

async function getRecords(zone, accounts, kv) {
  const cacheKey = `cache:rec:${zone.id}`;
  if (kv) {
    const cached = await kvGetCached(kv, cacheKey, "json", 900000);
    if (Array.isArray(cached)) return cached;
  }
  const records = [];
  let page = 1;
  while (true) {
    const res = await fetch(`${CF_API}/zones/${zone.id}/dns_records?per_page=100&page=${page}`, {
      headers: hdr(accounts[zone._acc].token),
      signal: withTimeout(),
    });
    const data = await res.json();
    if (!data.success || !data.result || data.result.length === 0) break;
    records.push(...data.result);
    if (data.result.length < 100) break;
    page++;
  }
  if (kv) await kvPutCached(kv, cacheKey, JSON.stringify(records), { expirationTtl: 900 }, 900000);
  return records;
}

async function invalidateCache(kv, zoneId) {
  if (!kv) return;
  try {
    await kvDeleteCached(kv, "cache:zones");
    if (zoneId) await kvDeleteCached(kv, `cache:rec:${zoneId}`);
  } catch (e) {
    console.error("CACHE_INV", String(e));
  }
}

async function getSettingsMap(zone, accounts) {
  const res = await fetch(`${CF_API}/zones/${zone.id}/settings`, { headers: hdr(accounts[zone._acc].token), signal: withTimeout() });
  const data = await res.json();
  const map = {};
  if (data.success && data.result) {
    for (const s of data.result) map[s.id] = s.value;
  }
  return map;
}

async function setSetting(zone, accounts, id, value) {
  const res = await fetch(`${CF_API}/zones/${zone.id}/settings/${id}`, {
    method: "PATCH",
    headers: hdr(accounts[zone._acc].token),
    body: JSON.stringify({ value }),
    signal: withTimeout(),
  });
  return res.json();
}

function normalizeName(name, zoneName) {
  if (!name) return name;
  if (name === "@" || name === zoneName) return zoneName;
  if (name.endsWith("." + zoneName)) return name;
  return `${name}.${zoneName}`;
}

function makeToken() {
  const b = new Uint8Array(6);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

// ===================== تاریخ شمسی (جلالی) + یادآور =====================
const TEHRAN_OFFSET_MS = 3.5 * 3600 * 1000;
const FA_DIGITS = "۰۱۲۳۴۵۶۷۸۹";

function _div(a, b) {
  return ~~(a / b);
}
function _mod(a, b) {
  return a - ~~(a / b) * b;
}
function _jalCal(jy) {
  const breaks = [-61, 9, 38, 199, 426, 686, 756, 818, 1111, 1181, 1210, 1635, 2060, 2097, 2192, 2262, 2324, 2394, 2456, 3178];
  const bl = breaks.length;
  const gy = jy + 621;
  let leapJ = -14;
  let jp = breaks[0];
  let jm, jump, leap, leapG, march, n, i;
  if (jy < jp || jy >= breaks[bl - 1]) throw new Error("bad jalali year");
  for (i = 1; i < bl; i += 1) {
    jm = breaks[i];
    jump = jm - jp;
    if (jy < jm) break;
    leapJ = leapJ + _div(jump, 33) * 8 + _div(_mod(jump, 33), 4);
    jp = jm;
  }
  n = jy - jp;
  leapJ = leapJ + _div(n, 33) * 8 + _div(_mod(n, 33) + 3, 4);
  if (_mod(jump, 33) === 4 && jump - n === 4) leapJ += 1;
  leapG = _div(gy, 4) - _div((_div(gy, 100) + 1) * 3, 4) - 150;
  march = 20 + leapJ - leapG;
  if (jump - n < 6) n = n - jump + _div(jump + 4, 33) * 33;
  leap = _mod(_mod(n + 1, 33) - 1, 4);
  if (leap === -1) leap = 4;
  return { leap, gy, march };
}
function _g2d(gy, gm, gd) {
  let d = _div((gy + _div(gm - 8, 6) + 100100) * 1461, 4) + _div(153 * _mod(gm + 9, 12) + 2, 5) + gd - 34840408;
  d = d - _div(_div(gy + 100100 + _div(gm - 8, 6), 100) * 3, 4) + 752;
  return d;
}
function _d2g(jdn) {
  let j = 4 * jdn + 139361631;
  j = j + _div(_div(4 * jdn + 183187720, 146097) * 3, 4) * 4 - 3908;
  const i = _div(_mod(j, 1461), 4) * 5 + 308;
  const gd = _div(_mod(i, 153), 5) + 1;
  const gm = _mod(_div(i, 153), 12) + 1;
  const gy = _div(j, 1461) - 100100 + _div(8 - gm, 6);
  return { gy, gm, gd };
}
function _j2d(jy, jm, jd) {
  const r = _jalCal(jy);
  return _g2d(r.gy, 3, r.march) + (jm - 1) * 31 - _div(jm, 7) * (jm - 7) + jd - 1;
}
function _d2j(jdn) {
  const gy = _d2g(jdn).gy;
  let jy = gy - 621;
  const r = _jalCal(jy);
  const jdn1f = _g2d(gy, 3, r.march);
  let k = jdn - jdn1f;
  if (k >= 0) {
    if (k <= 185) return { jy, jm: 1 + _div(k, 31), jd: _mod(k, 31) + 1 };
    k -= 186;
  } else {
    jy -= 1;
    k += 179;
    if (r.leap === 1) k += 1;
  }
  return { jy, jm: 7 + _div(k, 30), jd: _mod(k, 30) + 1 };
}
function toJalaali(gy, gm, gd) {
  return _d2j(_g2d(gy, gm, gd));
}
function toGregorian(jy, jm, jd) {
  return _d2g(_j2d(jy, jm, jd));
}
function jalaliToEpoch(jy, jm, jd, hh, mm) {
  const g = toGregorian(jy, jm, jd);
  return Date.UTC(g.gy, g.gm - 1, g.gd, hh, mm, 0, 0) - TEHRAN_OFFSET_MS;
}
function epochToJalali(ms) {
  const d = new Date(ms + TEHRAN_OFFSET_MS);
  return toJalaali(d.getUTCFullYear(), d.getUTCMonth() + 1, d.getUTCDate());
}
function fmtJalali(ms) {
  const j = epochToJalali(ms);
  const d = new Date(ms + TEHRAN_OFFSET_MS);
  const hh = String(d.getUTCHours()).padStart(2, "0");
  const mm = String(d.getUTCMinutes()).padStart(2, "0");
  return `${j.jy}/${String(j.jm).padStart(2, "0")}/${String(j.jd).padStart(2, "0")} - ${hh}:${mm}`;
}
function parseFaNums(s) {
  return String(s)
    .replace(/[۰-۹]/g, (d) => FA_DIGITS.indexOf(d))
    .replace(/[٠-٩]/g, (d) => "٠١٢٣٤٥٦٧٨٩".indexOf(d));
}
function tehranMidnightEpoch() {
  const d = new Date(Date.now() + TEHRAN_OFFSET_MS);
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()) - TEHRAN_OFFSET_MS;
}
const JALALI_MONTHS = ["فروردین", "اردیبهشت", "خرداد", "تیر", "مرداد", "شهریور", "مهر", "آبان", "آذر", "دی", "بهمن", "اسفند"];
function persianJyNow() {
  return epochToJalali(Date.now()).jy;
}
// افزودن مقدار نسبی (سال/ماه/روز) به «الان» به وقت تهران
function addRelative(years, months, days) {
  const base = new Date(Date.now() + TEHRAN_OFFSET_MS);
  let y = base.getUTCFullYear() + (years || 0);
  let m = base.getUTCMonth() + (months || 0);
  const day = base.getUTCDate();
  const hh = base.getUTCHours();
  const mm = base.getUTCMinutes();
  y += Math.floor(m / 12);
  m = ((m % 12) + 12) % 12;
  const dim = new Date(Date.UTC(y, m + 1, 0)).getUTCDate();
  const dd = Math.min(day, dim) + (days || 0);
  return Date.UTC(y, m, dd, hh, mm) - TEHRAN_OFFSET_MS;
}
function remWhenKb() {
  return [
    [{ text: "⏳ بعد از تایم مشخص", callback_data: "remrel" }],
    [{ text: "📅 انتخاب تاریخ", callback_data: "remabs" }],
    [{ text: "🔙 بازگشت", callback_data: "remnew" }],
  ];
}
const REM_WHEN_TEXT = "🕒 زمان یادآور:\nیکی از دو روش را انتخاب کنید:";
const REL_UNITS = { min: "دقیقه", hr: "ساعت", day: "روز", wk: "هفته", mon: "ماه", yr: "سال" };
function remRelKb() {
  return [
    [
      { text: "دقیقه", callback_data: "remrelu:min" },
      { text: "ساعت", callback_data: "remrelu:hr" },
    ],
    [
      { text: "روز", callback_data: "remrelu:day" },
      { text: "هفته", callback_data: "remrelu:wk" },
    ],
    [
      { text: "ماه", callback_data: "remrelu:mon" },
      { text: "سال", callback_data: "remrelu:yr" },
    ],
    [{ text: "🔙 بازگشت", callback_data: "remwhenback" }],
  ];
}
function addRel(unit, n) {
  const now = Date.now();
  if (unit === "min") return now + n * 60000;
  if (unit === "hr") return now + n * 3600000;
  if (unit === "day") return now + n * 86400000;
  if (unit === "wk") return now + n * 7 * 86400000;
  if (unit === "mon") return addRelative(0, n, 0);
  if (unit === "yr") return addRelative(n, 0, 0);
  return NaN;
}
function remYearKb() {
  const jy = persianJyNow();
  return [
    [{ text: String(jy), callback_data: `remabsy:${jy}` }, { text: String(jy + 1), callback_data: `remabsy:${jy + 1}` }],
    [{ text: String(jy + 2), callback_data: `remabsy:${jy + 2}` }, { text: String(jy + 3), callback_data: `remabsy:${jy + 3}` }],
    [{ text: "✍️ نوشتن دستی تاریخ", callback_data: "remabsman" }],
    [{ text: "🔙 بازگشت", callback_data: "remwhenback" }],
  ];
}
function remMonthKb(jy) {
  const rows = [];
  for (let i = 0; i < 12; i += 3) {
    rows.push(
      JALALI_MONTHS.slice(i, i + 3).map((name, k) => ({ text: name, callback_data: `remabsm:${jy}:${i + k + 1}` }))
    );
  }
  rows.push([{ text: "🔙 بازگشت", callback_data: "remabs" }]);
  return rows;
}
function remPlain(s) {
  return String(s == null ? "" : s).replace(/</g, "‹").replace(/>/g, "›");
}

async function getReminders(kv) {
  const list = await kvGetCached(kv, "reminders", "json", 20000);
  return Array.isArray(list) ? list : [];
}
async function saveReminders(kv, list) {
  await kvPutCached(kv, "reminders", JSON.stringify(list), undefined, 20000);
}
async function addReminder(kv, chatId, target, text, at) {
  const list = await getReminders(kv);
  const r = { id: makeToken(), by: chatId, target: target || null, text: text || "", at, created: Date.now() };
  list.push(r);
  await saveReminders(kv, list);
  return r;
}
async function getRemCfg(kv) {
  const c = await kvGetCached(kv, "rem_cfg", "json", 300000);
  const h = c && Number(c.leadHours);
  return { leadHours: Number.isFinite(h) ? Math.max(1, Math.min(720, h)) : 24 };
}
async function saveRemCfg(kv, cfg) {
  await kvPutCached(kv, "rem_cfg", JSON.stringify(cfg), undefined, 300000);
}
// ذخیرهٔ نهایی یادآور (عادی یا انقضای سرور). whenMs = زمانی که کاربر انتخاب کرده.
async function finalizeReminder(kv, chatId, pending, whenMs, send) {
  const prefix = "✅ یادآور ثبت شد.";
  let extra = "";
  let item = { id: makeToken(), by: chatId, target: pending.target || null, text: pending.text || "", at: whenMs, created: Date.now() };
  if (pending.mode === "expiry") {
    const lead = (await getRemCfg(kv)).leadHours;
    const expiryAt = whenMs;
    if (!Number.isFinite(expiryAt) || expiryAt <= Date.now()) {
      await send("⚠️ زمان انقضا باید در آینده باشد. دوباره بفرستید:");
      return false;
    }
    let at = expiryAt - lead * 3600 * 1000;
    if (at <= Date.now()) at = Date.now() + 1000;
    item.kind = "expiry";
    item.expiryAt = expiryAt;
    item.at = at;
    extra = `\n🗓 انقضا: ${fmtJalali(expiryAt)}\n🔔 یادآوری: ${fmtJalali(at)} (${lead} ساعت قبل)`;
  } else {
    if (!Number.isFinite(whenMs) || whenMs <= Date.now()) {
      await send("⚠️ زمان باید در آینده باشد. دوباره بفرستید:");
      return false;
    }
    extra = `\n🕒 ${fmtJalali(whenMs)}`;
  }
  await kv.delete(`pend:${chatId}`);
  const list = await getReminders(kv);
  list.push(item);
  await saveReminders(kv, list);
  await send(
    prefix +
      extra +
      (pending.target && pending.target.label ? `\n🎯 ${remPlain(pending.target.label)}` : "") +
      (pending.text ? `\n📝 ${remPlain(pending.text)}` : ""),
    [[{ text: "⏰ یادآورها", callback_data: "rem" }, { text: "🏠 منو", callback_data: "menu" }]]
  );
  return true;
}

// سرورها از هاست‌های همهٔ پنل‌ها (ساب‌ها) — کش‌اول، موازی، حذف تکراری، و با سقف زمانی قطعی
// سرورها را از «نودهای» پنل‌ها می‌گیریم (کش‌شده و سریع) — حذف تکراری بر اساس آدرس.
async function getServersPicker(kv, force) {
  const cached = await kvGetCached(kv, "servers_picker", "json", 3600000);
  const cachedArr = Array.isArray(cached) ? cached : [];
  if (!force && cachedArr.length) return cachedArr;

  const panels = await getPanels(kv);
  const monitors = await getNodeMonitors(kv);
  const out = [];
  const seen = new Set();
  const push = (panelName, n) => {
    const address = String((n && n.address) || "").trim();
    const name = String((n && n.name) || "").trim();
    const key = address || "n:" + name;
    if (!key || seen.has(key)) return;
    seen.add(key);
    out.push({ panel_name: panelName || "", host_id: name, remark: name, ip: address, status: (n && n.status) || "" });
  };

  // ۱) از وضعیت ذخیره‌شدهٔ مانیتورهای نود (بدون درخواست شبکه)
  for (const m of monitors) {
    const p = panels.find((x) => x.id === m.panel_id);
    const st = await getNodeState(kv, m.id);
    for (const k of Object.keys(st.nodes || {})) push(p && p.name, st.nodes[k]);
  }

  // ۲) اگر چیزی نبود، مستقیم از خود پنل‌ها بخوان (موازی، با سقف زمانی)
  if (!out.length) {
    const live = (async () => {
      const results = await Promise.allSettled(
        panels.map(async (p) => {
          const token = await panelLogin(p, 5000);
          if (!token) return { panel: p.name, list: [] };
          const list = await panelNodes(p, token);
          return { panel: p.name, list };
        })
      );
      for (const r of results) {
        if (r.status !== "fulfilled") continue;
        for (const n of r.value.list || []) push(r.value.panel, n);
      }
    })();
    await Promise.race([live.catch(() => {}), new Promise((res) => setTimeout(res, 8000))]);
  }

  if (out.length) await kvPutCached(kv, "servers_picker", JSON.stringify(out), { expirationTtl: 3600 }, 3600000);
  return out;
}

function recordLabel(r, zoneName) {
  let name = r.name;
  if (zoneName && name.endsWith("." + zoneName)) name = name.slice(0, -(zoneName.length + 1));
  const typeLabel = r.type === "CNAME" ? "cn" : r.type;
  return `${typeLabel}-${name}`;
}

function escHtml(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function code(s) {
  return `<code>${escHtml(s)}</code>`;
}

// ============================================================
// پیام مجوز توکن کلادفلر
// وقتی خطای کلادفلر به‌خاطر کمبود مجوز توکن باشد، یک نشانگر
// نامرئی به متن اضافه می‌شود تا لایهٔ ارسال پیام، دکمه‌های
// «بررسی مجدد» و «بازگشت» را زیر پیام بگذارد.
// ============================================================
const PERM_MARK = "\u2063";
const CF_PERM_CODES = [9109, 10000, 10001, 1010];

function isPermErrors(data) {
  const errors = Array.isArray(data) ? data : (data && data.errors) || data;
  const arr = Array.isArray(errors) ? errors : [];
  return arr.some((e) => e && CF_PERM_CODES.includes(Number(e.code)));
}

function cfErrText(data) {
  const errors = Array.isArray(data) ? data : (data && data.errors) || data;
  let out = JSON.stringify(errors, null, 2).substring(0, 3000);
  if (isPermErrors(data)) {
    out =
      PERM_MARK +
      out +
      "\n\n🔑 دسترسی توکن کافی نیست.\n" +
      "این بخش به مجوز بیشتری روی توکن این اکانت نیاز دارد.\n" +
      "از پنل کلادفلر برو به: Manage Account → Account API Tokens (یا My Profile → API Tokens)\n" +
      "→ توکن همین اکانت → Edit → مجوز لازم (مثلاً Zone → Zone Rulesets و Zone → Zone WAF) را اضافه کن، ذخیره کن و دوباره تلاش کن.";
  }
  return out;
}

function parentCb(data) {
  const d = String(data || "");
  const tok = (d.match(/[0-9a-f]{12}/) || [])[0];
  if (/^(zssl|zsec|zperf|zrules|zro|zrp|zrr|zrt|zrd|zrdy|zra|ztog|zval|zvset|zd|zpurge|zdev|zpause|zsearch):/.test(d) && tok) return `zset:${tok}`;
  if (/^zset:/.test(d)) return "zones";
  if (/^e:/.test(d) && tok) return `rback:${tok}`;
  if (/^sel/.test(d) && tok) return `rback:${tok}`;
  if (/^acc/.test(d)) return "accounts";
  if (/^(arv|arf)/.test(d)) return "arvan";
  if (/^(hz|ln)/.test(d)) return "providers";
  return "menu";
}

async function resolveIPs(name, kv) {
  const host = String(name).toLowerCase();
  const cacheKey = `dnscache:${host}`;
  if (kv) {
    const cached = await kvGetCached(kv, cacheKey, "json", 3600000);
    if (Array.isArray(cached)) return cached;
  }
  let ips = [];
  const sources = [
    { url: "https://cloudflare-dns.com/dns-query", accept: "application/dns-json" },
    { url: "https://dns.google/resolve", accept: "application/json" },
  ];
  for (const src of sources) {
    for (const type of ["A", "AAAA"]) {
      try {
        const res = await fetch(`${src.url}?name=${encodeURIComponent(host)}&type=${type}`, {
          headers: { accept: src.accept },
          signal: withTimeout(10000),
        });
        const data = await res.json();
        if (data && Array.isArray(data.Answer)) {
          for (const a of data.Answer) {
            if ((type === "A" && a.type === 1) || (type === "AAAA" && a.type === 28)) {
              if (a.data) ips.push(a.data);
            }
          }
        }
      } catch (e) {
        console.error("DNS_RES", String(e));
      }
      if (ips.length > 0) break;
    }
    if (ips.length > 0) break;
  }
  if (kv && ips.length) await kvPutCached(kv, cacheKey, JSON.stringify(ips), { expirationTtl: 3600 }, 3600000);
  return ips;
}

async function ipInfo(ip, kv) {
  const cacheKey = `ipinfo:${ip}`;
  if (kv) {
    const cached = await kvGetCached(kv, cacheKey, "json", 86400000);
    if (cached && cached.ip) return cached;
  }
  let info = null;
  try {
    const res = await fetch(`https://ipinfo.io/${encodeURIComponent(ip)}/json`, {
      headers: { accept: "application/json" },
      signal: withTimeout(10000),
    });
    const data = await res.json();
    if (data && data.ip) info = data;
  } catch (e) {
    console.error("IPINFO", String(e));
  }
  if (kv && info) await kvPutCached(kv, cacheKey, JSON.stringify(info), { expirationTtl: 86400 }, 86400000);
  return info;
}

function fmtIpInfo(ip, info) {
  if (!info) return code(ip);
  const loc = [info.city, info.country].filter(Boolean).join(", ");
  const org = (info.org || "").replace(/^AS\d+\s*/, "");
  const parts = [];
  if (loc) parts.push(loc);
  if (org) parts.push(org);
  return parts.length ? `${code(ip)} — ${parts.join(" • ")}` : code(ip);
}

// ===================== ساب‌های منتخب / تغییر سریع / برگشت خودکار =====================
function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function isIpv4(t) {
  const s = String(t).trim();
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return false;
  return s.split(".").every((o) => Number(o) <= 255);
}

function isIpv6(t) {
  const s = String(t).trim();
  return s.includes(":") && /^[0-9a-fA-F:.:%]+$/.test(s);
}

function isIpLike(t) {
  return isIpv4(t) || isIpv6(t);
}

function isNameLike(t) {
  return /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,120}$/.test(String(t).trim());
}

async function getFavs(kv, chatId) {
  let list = await kv.get(`favs:${chatId}`, "json");
  return Array.isArray(list) ? list : [];
}

async function saveFavs(kv, chatId, list) {
  await kv.put(`favs:${chatId}`, JSON.stringify(list));
}

function favExists(list, zoneId, recordId) {
  return list.some((f) => f.zone_id === zoneId && f.record_id === recordId);
}

function favShortName(f) {
  const zone = f.zone_name ? "." + f.zone_name : "";
  const n = f.name || "";
  return zone && n.endsWith(zone) ? n.slice(0, -zone.length) : n;
}

function favTypeShort(f) {
  return f.type === "CNAME" ? "cn" : f.type;
}

async function getRecordById(acc, zoneId, recordId, accounts) {
  const res = await fetch(`${CF_API}/zones/${zoneId}/dns_records/${recordId}`, {
    headers: hdr(accounts[acc].token),
    signal: withTimeout(),
  });
  const data = await res.json();
  return data && data.success ? data.result : null;
}

function diffSummary(name, prev, next) {
  let t = `✅ تغییر یافت\n\n📛 ساب‌دامین: ${code(name)}\n\n🔴 قبلی:\n${code(String(prev))}\n\n🟢 فعلی:\n${code(String(next))}`;
  return t;
}

async function renderFavsScreen(kv, chatId, accounts, edit) {
  const favs = await getFavs(kv, chatId);
  const lines = ["⭐ ساب‌های منتخب\n"];
  const kb = [];
  if (!favs.length) {
    lines.push(
      "📭 هنوز سابی به منتخب‌ها اضافه نشده.",
      "",
      "ساب‌هایی که زیاد IP/مقدارشان را عوض می‌کنید را اینجا بگذارید تا با یک لمس در دسترس باشند.",
      "• در صفحهٔ رکوردهای هر دامنه دکمهٔ «🗂 گروهی» را بزنید، ساب‌ها را انتخاب و «⭐ افزودن به منتخب‌ها» را بزنید.",
      "• روی هر رکورد که باز کنید هم دکمهٔ ستاره برای افزودن/حذف دارد.",
      "• یا از دکمهٔ «➕ افزودن ساب» زیر، دامنه و ساب را انتخاب کنید."
    );
  } else {
    kb.push(...grid2(favs.map((f, i) => ({ text: `${favTypeShort(f)} ${favShortName(f)} — ${f.zone_name}`, callback_data: `favopen:${i}` }))));
    lines.push(`تعداد: ${favs.length}\nبرای باز کردن و تغییر روی هر کدام بزنید.`);
  }
  kb.push([
    { text: "➕ افزودن ساب", callback_data: "favpickzone" },
    favs.length ? { text: "🗑 حذف از منتخب‌ها", callback_data: "favdel" } : EMPTY_BTN,
    { text: "🏠 منو", callback_data: "menu" },
  ]);
  await edit(lines.join("\n"), kb);
}

async function renderRecordDetail(kv, accounts, edit, chatId, token, recordId, backCb) {
  const session = await kv.get(`s:${token}`, "json");
  if (!session) return edit("⏳ نشست منقضی شده. دوباره /zones را بزنید.");
  const acc = session.acc;
  let r;
  if (session.provider === "arvan") {
    const records = await arvanGetAllRecords(await arvanToken(kv, acc), session.domain);
    r = records.find((rec) => rec.id === recordId);
    if (!r) return edit("❌ رکورد پیدا نشد.");
  } else {
    const recData = await (await fetch(`${CF_API}/zones/${session.zone_id}/dns_records/${recordId}`, {
      headers: hdr(accounts[acc].token),
      signal: withTimeout(),
    })).json();
    if (!recData.success) return edit("❌ رکورد پیدا نشد.");
    r = recData.result;
  }
  let ipBlock = "";
  if (r.type === "CNAME") {
    const ips = await resolveIPs(r.content, kv);
    if (ips.length > 0) {
      const lines = [];
      for (let i = 0; i < ips.length; i++) {
        const info = await ipInfo(ips[i], kv);
        lines.push(`${i + 1}) ${fmtIpInfo(ips[i], info)}`);
      }
      ipBlock = `\n🌍 IP های مقصد:\n` + lines.join("\n");
    } else {
      ipBlock = `\n🌍 IP مقصد: یافت نشد`;
    }
  } else if (r.type === "A" || r.type === "AAAA") {
    const info = await ipInfo(r.content, kv);
    ipBlock = `\n🌍 ${fmtIpInfo(r.content, info)}`;
  }
  const favs = await getFavs(kv, chatId);
  const zoneIdForFav = session.provider === "arvan" ? "arvan:" + session.domain : session.zone_id;
  const faved = favExists(favs, zoneIdForFav, recordId);
  const zoneName = session.provider === "arvan" ? session.domain : session.zone_name;
  const text =
    `✏️ ویرایش رکورد\n\n` +
    `📛 نام: ${code(r.name)}\n` +
    `🏷 نوع: ${code(r.type)}\n` +
    `💡 مقدار: ${code(r.content)}\n` +
    `⏱\u200F TTL: ${r.ttl === 1 || r.ttl === 120 ? (session.provider === "arvan" ? "پیش‌فرض" : "خودکار") : r.ttl}\n` +
    `🌐\u200F Proxy: ${r.proxied ? "روشن" : "خاموش"}\n` +
    `📁 دامنه: ${code(zoneName)}` +
    ipBlock;
  await edit(text, [
    ...grid2([
      { text: "✏️ تغییر مقدار", callback_data: `ev:${token}:${recordId}` },
      { text: "🔄 تغییر نوع", callback_data: `ct:${token}:${recordId}` },
      { text: "⏱ تغییر TTL", callback_data: `et:${token}:${recordId}` },
      { text: "🔄 تغییر Proxy", callback_data: `ep:${token}:${recordId}` },
    ]),
    [{ text: "🗑 حذف رکورد", callback_data: `d:${token}:${recordId}` }],
    [{ text: faved ? "⭐ حذف از منتخب‌ها" : "⭐ افزودن به منتخب‌ها", callback_data: `favtg:${token}:${recordId}` }],
    [{ text: "🔙 بازگشت", callback_data: backCb || `rback:${token}` }],
  ]);
}

async function redrawRecordDetailNav(kv, accounts, botToken, chatId, messageId) {
  const nav = await kv.get(`dd:${chatId}:${messageId}`, "json");
  if (!nav) return;
  const edit = (text, kb) => editMessage(botToken, chatId, messageId, text, kb);
  await renderRecordDetail(kv, accounts, edit, chatId, nav.token, nav.recordId, nav.backCb);
}

async function redrawRecordsList(kv, accounts, botToken, chatId, messageId, token, page) {
  const edit = (text, kb) => editMessage(botToken, chatId, messageId, text, kb);
  const session = await kv.get(`s:${token}`, "json");
  if (!session) return edit("⏳ نشست منقضی شده.");
  if (session.provider === "arvan") {
    const records = await arvanGetAllRecords(await arvanToken(kv, session.acc), session.domain);
    if (records.length === 0) {
      const kb = [
        [{ text: "➕ افزودن", callback_data: `addz:${token}` }],
        [{ text: "🔙 بازگشت", callback_data: "arvan" }],
      ];
      return edit(`📭 رکوردی برای ${session.domain} باقی نمانده.`, kb);
    }
    await renderArvanRecords(session.domain, records, token, page || 0, edit);
    return;
  }
  const zone = await getZoneById(session.zone_id, session.acc, accounts);
  if (!zone) return edit("❌ دامنه پیدا نشد.");
  const records = await getRecords(zone, accounts, kv);
  if (records.length === 0) {
    const kb = [
      [{ text: "➕ افزودن", callback_data: `addz:${token}` }],
      [{ text: "⚙️ تنظیمات", callback_data: `zset:${token}` }],
      [{ text: "🔙 بازگشت", callback_data: "zones" }],
    ];
    return edit(`📭 رکوردی برای ${zone.name} باقی نمانده.`, kb);
  }
  await renderRecords(zone, records, token, page || 0, edit);
}

async function redrawSearchResultsNav(kv, accounts, botToken, chatId, messageId, srToken) {
  const edit = (text, kb) => editMessage(botToken, chatId, messageId, text, kb);
  const stored = await kv.get(`sr:${srToken}`, "json");
  if (!stored) return edit("⏳ نشست منقضی شده.");
  await renderSearchResults(srToken, stored.results, stored.query, stored.field, edit);
}

async function redrawMenuNav(kv, botToken, chatId, messageId) {
  const edit = (text, kb) => editMessage(botToken, chatId, messageId, text, kb);
  await edit(mainMenuText(), mainMenuKeyboard());
}

// ===================== Hetzner =====================
function hzHdr(token) {
  return { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
}

async function hzFetch(token, path, opts = {}) {
  const res = await fetch(HETZNER_API + path, { ...opts, headers: hzHdr(token), signal: withTimeout(15000) });
  const text = await res.text();
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return {};
  }
}

async function getArvanAccounts(kv) {
  let list = await kvGetCached(kv, "arvan_accounts", "json");
  if (!Array.isArray(list)) list = [];
  return list;
}

async function arvanToken(kv, i) {
  const list = await getArvanAccounts(kv);
  return list[i] ? list[i].token : "";
}

async function saveArvanAccounts(kv, list) {
  await kvPutCached(kv, "arvan_accounts", JSON.stringify(list));
}

async function getHzAccounts(kv) {
  let list = await kvGetCached(kv, "hz_accounts", "json");
  if (!Array.isArray(list)) list = [];
  return list;
}

async function saveHzAccounts(kv, list) {
  await kvPutCached(kv, "hz_accounts", JSON.stringify(list));
}

function maskHzToken(t) {
  if (!t) return "";
  if (t.length <= 12) return t.slice(0, 6) + "…";
  return t.slice(0, 10) + "…" + t.slice(-4);
}

async function hzGetAll(token, path) {
  const out = [];
  let page = 1;
  while (true) {
    const data = await hzFetch(token, `${path}?per_page=50&page=${page}`);
    let arr = null;
    for (const k of Object.keys(data)) {
      if (Array.isArray(data[k])) {
        arr = data[k];
        break;
      }
    }
    if (!arr || arr.length === 0) break;
    out.push(...arr);
    if (arr.length < 50) break;
    page++;
  }
  return out;
}

function hzServerListText(s) {
  const ip = s.public_net && s.public_net.ipv4 ? s.public_net.ipv4.ip : "—";
  return `${s.status === "running" ? "🟢" : s.status === "off" ? "🔴" : "🟡"} ${s.name} (${ip})`;
}

function hzGb(bytes) {
  return Math.round(((bytes || 0) / 1024 ** 3) * 1000) / 1000;
}

// ===================== Linode =====================
function lnHdr(token) {
  return { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
}

async function lnFetch(token, path, opts = {}) {
  const res = await fetch(LINODE_API + path, { ...opts, headers: lnHdr(token), signal: AbortSignal.timeout(20000) });
  const text = await res.text();
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return {};
  }
}

async function getLnAccounts(kv) {
  let list = await kvGetCached(kv, "ln_accounts", "json");
  if (!Array.isArray(list)) list = [];
  return list;
}

async function saveLnAccounts(kv, list) {
  await kvPutCached(kv, "ln_accounts", JSON.stringify(list));
}

function maskLnToken(t) {
  if (!t) return "";
  if (t.length <= 12) return t.slice(0, 6) + "…";
  return t.slice(0, 10) + "…" + t.slice(-4);
}

async function lnGetAll(token, path) {
  const out = [];
  let page = 1;
  for (;;) {
    const sep = path.includes("?") ? "&" : "?";
    const data = await lnFetch(token, `${path}${sep}page=${page}&page_size=500`);
    const arr = Array.isArray(data.data) ? data.data : [];
    out.push(...arr);
    if (!data.pages || page >= data.pages) break;
    page++;
  }
  return out;
}

function lnRegionPrice(type, region) {
  if (!type) return {};
  const rp = (type.region_prices || []).find((p) => p.id === region);
  return rp || type.price || {};
}

function lnGb(mb) {
  return Math.round(((mb || 0) / 1024) * 100) / 100;
}

function lnServerListText(s) {
  const ip = (s.ipv4 && s.ipv4[0]) || "—";
  const st = s.status === "running" ? "🟢" : s.status === "offline" ? "🔴" : "🟡";
  return `${st} ${s.label} (${ip})`;
}

function lnErr(r) {
  if (!r) return "unknown";
  if (Array.isArray(r.errors) && r.errors.length) {
    const m = r.errors.map((e) => e.reason || e.field || "").filter(Boolean).join("; ");
    if (m) return m;
  }
  return r.error || "error";
}

function lnRandomPass() {
  return "Ln" + makeToken() + "aA1!";
}

// ===================== ArvanCloud =====================
function arvanHdr(token) {
  return { Authorization: `APIKEY ${token}`, "Content-Type": "application/json", Accept: "application/json" };
}

async function arvanFetch(token, path, opts = {}, timeoutMs = 30000) {
  const res = await fetch(ARVAN_API + path, { ...opts, headers: arvanHdr(token), signal: AbortSignal.timeout(timeoutMs) });
  const text = await res.text();
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return {};
  }
}

async function arvanGetAllDomains(token) {
  const out = [];
  let page = 1;
  while (true) {
    const data = await arvanFetch(token, `/domains?per_page=50&page=${page}`);
    let arr = null;
    if (data.data && Array.isArray(data.data)) {
      arr = data.data;
    } else if (data.result && Array.isArray(data.result)) {
      arr = data.result;
    }
    if (!arr || arr.length === 0) break;
    for (const d of arr) {
      const name = d.domain || d.name || d.domain_name || "";
      if (name) out.push({ domain: name, ...d });
    }
    if (arr.length < 50) break;
    page++;
  }
  return out;
}

function normalizeArvanRecord(record, domain) {
  const rawName = record.name || "@";
  const fullName = rawName === "@" ? domain : (rawName.endsWith("." + domain) ? rawName : rawName + "." + domain);
  const getValue = (v) => {
    if (Array.isArray(v) && v.length) {
      const first = v[0];
      if (typeof first === "object") return first.ip || first.host || first.text || first.value || first.content || "";
      return String(first);
    }
    if (typeof v === "object") return v.ip || v.host || v.text || v.value || v.content || "";
    return v != null ? String(v) : "";
  };
  const content = getValue(record.value) || getValue(record.values) || getValue(record.content) || getValue(record.data);
  const type = (record.type || "A").toUpperCase();
  return {
    id: record.id || record.uuid || record.record_id || "",
    type,
    name: fullName,
    content,
    proxied: !!record.cloud,
    ttl: record.ttl || 120,
    provider: "arvan",
    domain,
    raw: record,
  };
}

async function arvanGetAllRecords(token, domain) {
  const out = [];
  let page = 1;
  while (true) {
    const data = await arvanFetch(token, `/domains/${encodeURIComponent(domain)}/dns-records?per_page=100&page=${page}`);
    let arr = null;
    if (data.data && Array.isArray(data.data)) {
      arr = data.data;
    } else if (data.result && Array.isArray(data.result)) {
      arr = data.result;
    } else if (data.data && typeof data.data === "object") {
      arr = data.data.records || data.data.dns_records || data.data.items || null;
    }
    if (!arr || !Array.isArray(arr) || arr.length === 0) break;
    for (const r of arr) {
      if (typeof r === "object") {
        const norm = normalizeArvanRecord(r, domain);
        if (norm.id) out.push(norm);
      }
    }
    if (arr.length < 100) break;
    page++;
  }
  return out;
}

async function arvanUpdateRecord(token, domain, record, newContent) {
  const rid = record.id || record.raw?.id || record.raw?.uuid || "";
  if (!rid) return { success: false, errors: [{ message: "Missing record id" }] };
  const url = `/domains/${encodeURIComponent(domain)}/dns-records/${rid}`;
  const raw = record.raw || {};
  const rtype = (record.type || raw.type || "A").toUpperCase();
  const ttl = raw.ttl != null ? raw.ttl : record.ttl;
  const cloudVal = record.proxied != null ? record.proxied : (raw.cloud || false);
  let valuePayload = [];
  if (rtype === "A" || rtype === "AAAA") {
    const extra = {};
    for (const k of Object.keys(raw)) {
      if (!["id", "created_at", "updated_at", "status", "name", "type", "ttl", "cloud", "value", "values"].includes(k)) {
        extra[k] = raw[k];
      }
    }
    extra.ip = newContent;
    valuePayload = [extra];
  } else if (rtype === "CNAME" || rtype === "NS") {
    const extra = {};
    for (const k of Object.keys(raw)) {
      if (!["id", "created_at", "updated_at", "status", "name", "type", "ttl", "cloud", "value", "values"].includes(k)) {
        extra[k] = raw[k];
      }
    }
    extra.host = newContent;
    valuePayload = [extra];
  } else if (rtype === "TXT") {
    const extra = {};
    for (const k of Object.keys(raw)) {
      if (!["id", "created_at", "updated_at", "status", "name", "type", "ttl", "cloud", "value", "values"].includes(k)) {
        extra[k] = raw[k];
      }
    }
    extra.text = newContent;
    valuePayload = [extra];
  } else {
    valuePayload = [newContent];
  }
  const payload = {
    type: rtype.toLowerCase(),
    name: raw.name || record.name || "@",
    value: valuePayload,
    cloud: cloudVal,
  };
  if (ttl != null && ttl !== 0 && ttl !== "") payload.ttl = ttl;
  if (rid) payload.id = rid;
  let res = await arvanFetch(token, url, { method: "PUT", body: JSON.stringify(payload) });
  if (res.success !== false) return res;
  res = await arvanFetch(token, url, { method: "PATCH", body: JSON.stringify(payload) });
  return res;
}

async function arvanCreateRecord(token, domain, rtype, name, content, proxied) {
  const shortName = name === domain ? "@" : (name.endsWith("." + domain) ? name.slice(0, -(domain.length + 1)) : name);
  let valuePayload = [];
  const rtypeU = rtype.toUpperCase();
  if (rtypeU === "A" || rtypeU === "AAAA") {
    valuePayload = [{ ip: content }];
  } else if (rtypeU === "CNAME" || rtypeU === "NS") {
    valuePayload = [{ host: content }];
  } else if (rtypeU === "TXT") {
    valuePayload = [{ text: content }];
  } else {
    valuePayload = [content];
  }
  const payload = {
    type: rtypeU.toLowerCase(),
    name: shortName,
    value: valuePayload,
    cloud: rtypeU === "A" || rtypeU === "AAAA" || rtypeU === "CNAME" ? !!proxied : false,
  };
  const res = await arvanFetch(token, `/domains/${encodeURIComponent(domain)}/dns-records`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
  return res;
}

async function arvanDeleteRecord(token, domain, rid) {
  const res = await arvanFetch(token, `/domains/${encodeURIComponent(domain)}/dns-records/${rid}`, { method: "DELETE" });
  return res;
}

function maskArvanToken(t) {
  if (!t) return "";
  if (t.length <= 12) return t.slice(0, 6) + "…";
  return t.slice(0, 10) + "…" + t.slice(-4);
}

// ===================== SSL Monitor =====================
async function getSslMonitors(kv) {
  let list = await kvGetCached(kv, "ssl_monitor", "json");
  if (!Array.isArray(list)) list = [];
  return list;
}

async function saveSslMonitors(kv, list) {
  await kvPutCached(kv, "ssl_monitor", JSON.stringify(list));
}

async function sslProbe(host, port) {
  try {
    const url = `https://uptimepage.dev/tools/ssl-certificate-checker/probe?host=${encodeURIComponent(host)}&port=${Number(port) || 443}`;
    const res = await fetch(url, { headers: { accept: "application/json" }, signal: withTimeout(15000) });
    return await res.json();
  } catch (e) {
    console.error("SSL_PROBE", String(e));
    return null;
  }
}

async function sslCheckAll(kv) {
  const monitors = await getSslMonitors(kv);
  const out = [];
  for (const m of monitors) {
    const r = await sslProbe(m.host, m.port);
    out.push({ host: m.host, threshold: m.threshold, result: r });
  }
  return out;
}

function sslResultLine(item) {
  const r = item.result;
  if (!r) return `⚪ ${item.host} — خطا در بررسی`;
  if (r.ok !== true) return `⚪ ${item.host} — ${r.error || "پیدا نشد"}`;
  const emoji = r.expired ? "⛔" : r.days_remaining <= Number(item.threshold) ? "🔴" : r.days_remaining <= 10 ? "🟠" : "🟢";
  const state = r.expired ? "منقضی شده" : `${r.days_remaining} روز مانده`;
  return `${emoji} ${r.host} — ${state}${r.expired ? "" : ` (آستانه: ${item.threshold})`}`;
}

async function runSslMonitor(env) {
  const kv = env.BOT_KV;
  if (!kv) return;
  const botToken = env.BOT_TOKEN || BOT_TOKEN;
  const admins = await getAdmins(kv, env);
  const monitors = await getSslMonitors(kv);
  if (!monitors.length) return;
  for (const m of monitors) {
    const r = await sslProbe(m.host, m.port);
    if (!r || r.ok !== true) continue;
    const th = Number(m.threshold) || 5;
    if (r.expired || r.days_remaining <= th) {
      const msg =
        `${r.expired ? "⛔ گواهی SSL منقضی شده است!" : "⚠️ گواهی SSL رو به انقضا است!"}\n\n` +
        `🌐 ${code(r.host)}\n` +
        `⏳ باقی‌مانده: ${code(r.days_remaining + " روز")}\n` +
        `📅 تاریخ انقضا: ${code((r.not_after || "").slice(0, 10))}\n` +
        `🏢 صادرکننده: ${code(r.issuer_common_name || "—")}`;
      for (const a of admins) {
        try {
          await sendMessage(botToken, a, msg);
        } catch (e) {
          console.error("SSL_ALERT", String(e));
        }
      }
    }
  }
}

// ===================== Panel / Server registry (shared with Node monitor) =====================
const PANEL_OFFSET_MS = 3.5 * 3600 * 1000; // Asia/Tehran

async function getPanels(kv) {
  let list = await kvGetCached(kv, "panels", "json");
  if (!Array.isArray(list)) list = [];
  return list;
}

async function savePanels(kv, list) {
  await kvPutCached(kv, "panels", JSON.stringify(list));
}

function chunkText(text, limit = 3800) {
  const chunks = [];
  let cur = "";
  for (const line of text.split("\n")) {
    if (cur.length + line.length + 1 > limit) {
      chunks.push(cur);
      cur = line;
    } else {
      cur = cur ? cur + "\n" + line : line;
    }
  }
  if (cur) chunks.push(cur);
  return chunks;
}

async function sendPanelMsg(botToken, chatId, text) {
  for (const chunk of chunkText(text)) {
    try {
      await tg(botToken, "sendMessage", {
        chat_id: chatId,
        text: chunk,
        parse_mode: "HTML",
        disable_web_page_preview: true,
      });
    } catch (e) {
      console.error("PANEL_MSG", String(e));
    }
  }
}

async function panelLogin(p, timeoutMs) {
  try {
    const res = await fetch(`${p.url.replace(/\/+$/, "")}/api/admin/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ username: p.username, password: p.password }),
      signal: AbortSignal.timeout(timeoutMs || 20000),
    });
    const data = await res.json();
    if (!res.ok || !data.access_token) return null;
    return data.access_token;
  } catch (e) {
    console.error("PANEL_LOGIN", String(e));
    return null;
  }
}

// ===================== Node Monitor (push / webhook) =====================
const NODE_DOWN_STATES = ["connected", "up", "online", "running", "healthy"];
const NODE_OFF_STATES = ["error", "down", "offline", "stopped", "unreachable", "off"];
const NODE_MID_STATES = ["connecting", "connecting_to_server", "restarting", "starting"];

async function getNodeMonitors(kv) {
  let list = await kvGetCached(kv, "node_monitors", "json");
  if (!Array.isArray(list)) list = [];
  return list;
}

async function saveNodeMonitors(kv, list) {
  await kvPutCached(kv, "node_monitors", JSON.stringify(list));
}

async function getNodeState(kv, id) {
  const s = await kvGetCached(kv, `ndst:${id}`, "json");
  if (s && s.nodes && typeof s.nodes === "object") return JSON.parse(JSON.stringify(s));
  return { nodes: {}, ts: null };
}

function _nodeSig(s) {
  if (!s || !s.nodes) return "";
  return Object.keys(s.nodes)
    .sort()
    .map((k) => k + ":" + s.nodes[k].status)
    .join("|");
}

async function saveNodeState(kv, id, s) {
  const key = `ndst:${id}`;
  const prev = memGet("kv:" + key);
  // فقط وقتی وضعیت نودها واقعاً تغییر کرده بنویس (صرفه‌جویی در write).
  if (prev && _nodeSig(prev) === _nodeSig(s)) return;
  await kvPutCached(kv, key, JSON.stringify(s));
}

async function cacheSelfUrl(kv, origin) {
  if (!kv || !origin) return;
  if (origin === _lastSelfOrigin) return;
  _lastSelfOrigin = origin;
  try {
    const cur = await kvGetCached(kv, "self_url", undefined, 3600000);
    if (!cur) await kvPutCached(kv, "self_url", origin, undefined, 3600000);
  } catch (e) {
    console.error("SELF_URL", String(e));
  }
}

async function selfUrlBase(env, kv) {
  if (env.WORKER_URL) return String(env.WORKER_URL).replace(/\/+$/, "");
  if (kv) {
    const cur = await kvGetCached(kv, "self_url", undefined, 3600000);
    if (cur) return cur;
  }
  return "";
}

function nodeStatusDir(st) {
  const s = String(st || "").toLowerCase();
  if (NODE_DOWN_STATES.includes(s)) return "up";
  if (NODE_OFF_STATES.includes(s)) return "down";
  return "mid";
}

function nodeStatusEmoji(st) {
  const d = nodeStatusDir(st);
  if (d === "up") return "🟢";
  if (d === "down") return "🔴";
  const s = String(st || "").toLowerCase();
  return s === "disabled" ? "⚪" : "🟡";
}

function nodeStatusLabel(st) {
  const s = String(st || "").toLowerCase();
  if (NODE_DOWN_STATES.includes(s)) return "آنلاین";
  if (NODE_OFF_STATES.includes(s)) return "قطع";
  if (NODE_MID_STATES.includes(s)) return "در حال اتصال";
  if (s === "disabled") return "غیرفعال";
  if (!s || s === "unknown") return "نامشخص";
  return String(st);
}

function ndFmtTs(iso) {
  if (!iso) return "";
  try {
    const d = new Date(new Date(iso).getTime() + PANEL_OFFSET_MS);
    return d.toISOString().replace("T", " ").slice(0, 16);
  } catch (e) {
    return "";
  }
}

async function panelNodes(p, token) {
  const base = p.url.replace(/\/+$/, "");
  const res = await fetch(`${base}/api/nodes`, {
    headers: { Authorization: `Bearer ${token}` },
    signal: withTimeout(15000),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  let arr = Array.isArray(data) ? data : (data && (data.nodes || data.items || data.result)) || [];
  const out = [];
  for (const n of arr) {
    if (!n) continue;
    out.push({
      name: String(n.name || n.node_name || n.id || ""),
      status: String(n.status || n.node_status || "unknown"),
      address: n.address || null,
      port: n.port || null,
      version: n.xray_version || n.version || null,
      reason: n.message || n.error || n.status_message || null,
      updated: n.updated_at || n.last_status_change || null,
    });
  }
  return out;
}

async function nodeSyncFromPanel(m, kv) {
  const panels = await getPanels(kv);
  const panel = panels.find((p) => p.id === m.panel_id);
  if (!panel) return { error: "پنل مرتبط پیدا نشد (احتمالاً از لیست پنل‌ها حذف شده)." };
  const token = await panelLogin(panel);
  if (!token) return { error: "ورود به پنل ناموفق؛ نام‌کاربری/رمز را در «ثبت پنل» بررسی کنید." };
  let list;
  try {
    list = await panelNodes(panel, token);
  } catch (e) {
    return { error: `خطا در خواندن نودها: ${e && e.message ? e.message : e}` };
  }
  const st = await getNodeState(kv, m.id);
  const now = new Date().toISOString();
  for (const n of list) {
    const prev = st.nodes[n.name];
    st.nodes[n.name] = {
      name: n.name,
      status: n.status,
      address: n.address,
      version: n.version,
      reason: n.reason || null,
      ts: now,
      first_seen: (prev && prev.first_seen) || now,
    };
  }
  st.ts = now;
  await saveNodeState(kv, m.id, st);
  return { nodes: list };
}

async function runNodePoll(env) {
  const kv = env.BOT_KV;
  if (!kv) return;
  const botToken = env.BOT_TOKEN || BOT_TOKEN;
  try {
    const panels = await getPanels(kv);
    const monitors = await getNodeMonitors(kv);
    if (!panels.length || !monitors.length) return;
    const admins = await getAdmins(kv, env);
    const now = new Date().toISOString();
    for (const m of monitors) {
      if (m.enabled === false) continue;
      const panel = panels.find((p) => p.id === m.panel_id);
      if (!panel) continue;
      const token = await panelLogin(panel);
      if (!token) continue;
      let list;
      try {
        list = await panelNodes(panel, token);
      } catch (e) {
        console.error("NDPOLL_FETCH", e && e.message ? e.message : String(e));
        continue;
      }
      const st = await getNodeState(kv, m.id);
      const panelName = (panel && panel.name) || m.name;
      for (const n of list) {
        const name = String(n.name || "");
        if (!name) continue;
        const prev = st.nodes[name];
        const dir = nodeStatusDir(n.status);
        if (prev && (dir === "up" || dir === "down")) {
          const prevDir = nodeStatusDir(prev.status);
          if (prevDir && prevDir !== dir && !(m.excluded || []).includes(name)) {
            const ts = ndFmtTs(now);
            const msg =
              dir === "down"
                ? `🚨 نود قطع شد!\n🖥 پنل: ${escHtml(panelName)}\n🖧 نود: ${code(name)}\n⏱ زمان: ${ts} به وقت ایران\n🔎 علت: ${n.reason ? escHtml(String(n.reason)) : "—"}`
                : `✅ نود وصل شد!\n🖥 پنل: ${escHtml(panelName)}\n🖧 نود: ${code(name)}\n⏱ زمان: ${ts} به وقت ایران${n.reason ? `\nℹ️ ${escHtml(String(n.reason))}` : ""}`;
            for (const a of admins) await sendPanelMsg(botToken, a, msg);
          }
        }
        st.nodes[name] = {
          name,
          status: n.status,
          address: n.address,
          version: n.version,
          reason: n.reason || null,
          ts: now,
          first_seen: (prev && prev.first_seen) || now,
        };
      }
      st.ts = now;
      await saveNodeState(kv, m.id, st);
    }
  } catch (e) {
    console.error("NDPOLL", e && e.stack ? e.stack : String(e));
  }
}

async function renderNodeHome(edit, kv) {
  const panels = await getPanels(kv);
  const monitors = await getNodeMonitors(kv);
  const lines = ["🖥 مانیتور نود پاسارگارد\n"];
  const kb = [];
  if (!panels.length) {
    lines.push(
      "📭 هنوز پنلی ثبت نشده.\n\n" +
        "ابتدا با «➕ افزودن پنل» پنل پاسارگارد خود را ثبت کنید، سپس برای همان پنل یک «مانیتور نود» بسازید تا قطع/وصل شدن نودهای آن به شما هشدار داده شود.\n\n" +
        "هشدارها فقط به‌صورت رویداد (push) و بدون هیچ کرون‌جابی دریافت می‌شوند؛ لیست نودها هم فقط وقتی دکمه «همگام‌سازی» را می‌زنید از پنل خوانده می‌شود."
    );
  } else {
    lines.push("🗂 پنل‌ها:");
    for (let i = 0; i < panels.length; i++) {
      const p = panels[i];
      const m = monitors.find((x) => x.panel_id === p.id);
      let sum = "بدون مانیتور نود";
      if (m) {
        const st = await getNodeState(kv, m.id);
        const names = Object.keys(st.nodes);
        let on = 0;
        let off = 0;
        let mid = 0;
        for (const nm of names) {
          const d = nodeStatusDir(st.nodes[nm].status);
          if (d === "up") on++;
          else if (d === "down") off++;
          else mid++;
        }
        sum = names.length
          ? `${names.length} نود — ${on} آنلاین / ${off} قطع${mid ? ` / ${mid} نامشخص` : ""}${m.enabled === false ? " ⏸ متوقف" : ""}`
          : "بدون وضعیت ثبت‌شده";
      }
      lines.push(`${i + 1}) ${escHtml(p.name)} — ${escHtml(p.url)}`);
      lines.push(`   ${sum}`);
      kb.push([{ text: `🖥 ${p.name}`, callback_data: `pnd:${i}` }]);
    }
  }
  const panelRows = kb.slice();
  const outKb = [[{ text: "➕ افزودن پنل", callback_data: "pnladd" }]];
  for (let i = 0; i < panelRows.length; i++) {
    const row = panelRows[i].slice();
    if (i === 0) row.push({ text: "🧭 تعویض خودکار هاست فیلتر", callback_data: "hf" });
    outKb.push(row);
  }
  if (!panelRows.length) outKb.push([{ text: "🧭 تعویض خودکار هاست فیلتر", callback_data: "hf" }]);
  if (panels.length && panels.some((p) => !monitors.some((x) => x.panel_id === p.id))) {
    outKb.push([{ text: "➕ ساخت مانیتور نود", callback_data: "nda" }]);
  }
  outKb.push([{ text: "🏠 منو", callback_data: "menu" }, { text: "ℹ️ راهنما", callback_data: "ndhelp" }]);
  await edit(lines.join("\n"), outKb);
}

function sortedNodeNames(st) {
  return Object.keys(st.nodes).sort((a, b) => nodeStatusDir(st.nodes[a].status).localeCompare(nodeStatusDir(st.nodes[b].status)));
}

function nodeButtonRows(mi, m, st) {
  const names = sortedNodeNames(st);
  const exc = new Set(m.excluded || []);
  const rows = [];
  names.forEach((nm, ni) => {
    const nd = st.nodes[nm];
    const short = nm.length > 16 ? nm.substring(0, 15) + "…" : nm;
    rows.push([
      { text: `${nodeStatusEmoji(nd.status)} ${short}`, callback_data: `ndi:${mi}:${ni}` },
      { text: "🌐", callback_data: `ndip:${mi}:${ni}` },
      { text: exc.has(nm) ? "✅" : "🚫", callback_data: `ndx:${mi}:${ni}` },
    ]);
  });
  return rows;
}

async function renderPanelDetail(panels, monitors, idx, edit, kv) {
  const p = panels[idx];
  if (!p) return edit("❌ پنل پیدا نشد.", [[{ text: "🖥 مانیتور نود پاسارگارد", callback_data: "nd" }]]);
  const m = monitors.find((x) => x.panel_id === p.id);
  const lines = ["🖥 پنل «" + escHtml(p.name) + "»"];
  lines.push("🌐 " + code(p.url));
  lines.push("👤 " + code(p.username || "—"));
  lines.push("");
  let st = { nodes: {} };
  if (!m) {
    lines.push("📭 هنوز «مانیتور نود» برای این پنل ساخته نشده.");
    lines.push("بعد از ساخت، قطع/وصل شدن نودهای پنل به‌صورت رویداد (وبهوک) به شما هشدار داده می‌شود.");
  } else {
    lines.push("🧠 مانیتور نود: " + (m.enabled === false ? "⏸ متوقف" : "▶️ فعال"));
    st = await getNodeState(kv, m.id);
    if (st.ts) lines.push(`🕐 آخرین به‌روزرسانی: ${ndFmtTs(st.ts)}`);
    const names = sortedNodeNames(st);
    if (!names.length) {
      lines.push("", "📭 هنوز وضعیتی ثبت نشده.", "• دکمه «🔄 همگام‌سازی با پنل» را بزنید یا وب‌هوک را وصل کنید.");
    } else {
      lines.push("", `🖧 نودها (${names.length}): روی دکمهٔ هر نود بزنید · 🌐 = آی‌پی · 🚫/✅ = استثنا`);
    }
  }
  const kb = [];
  if (m) {
    const mi = monitors.indexOf(m);
    kb.push([{ text: "🔄 همگام‌سازی با پنل", callback_data: `ndsync:${mi}` }]);
    kb.push([{ text: m.enabled === false ? "▶️ فعال‌سازی هشدار" : "⏸ توقف هشدار", callback_data: `ndtg:${mi}` }]);
    kb.push([{ text: "🔗 وب‌هوک", callback_data: `ndhook:${mi}` }, { text: "🧪 هشدار آزمایشی", callback_data: `ndtest:${mi}` }]);
    kb.push(...nodeButtonRows(mi, m, st));
    kb.push([{ text: "🗑 حذف مانیتور نود", callback_data: `nddel:${mi}` }]);
  } else {
    kb.push([{ text: "➕ ساخت مانیتور نود", callback_data: `nda:${p.id}` }]);
  }
  kb.push([{ text: "🗑 حذف پنل", callback_data: `pnlx:${idx}` }]);
  kb.push([{ text: "🔙 بازگشت", callback_data: "nd" }]);
  await edit(lines.join("\n"), kb);
}

async function renderNodeMonitor(monitors, idx, edit, kv) {
  const m = monitors[idx];
  if (!m) return edit("❌ مانیتور نود پیدا نشد.");
  const panels = await getPanels(kv);
  const panel = panels.find((p) => p.id === m.panel_id);
  const st = await getNodeState(kv, m.id);
  const lines = ["🖥 مانیتور نود «" + escHtml(m.name) + "»", "وضعیت: " + (m.enabled === false ? "⏸ متوقف" : "▶️ فعال")];
  if (panel) lines.push(`🧠 پنل مرتبط: ${escHtml(panel.name)}`);
  if (st.ts) lines.push(`🕐 آخرین به‌روزرسانی: ${ndFmtTs(st.ts)}`);
  const names = sortedNodeNames(st);
  if (!names.length) {
    lines.push("", "📭 هنوز وضعیتی ثبت نشده.", "• دکمه «🔄 همگام‌سازی با پنل» را بزنید یا وب‌هوک را وصل کنید.");
  } else {
    lines.push("", `🖧 نودها (${names.length}): روی دکمهٔ هر نود بزنید · 🌐 = آی‌پی · 🚫/✅ = استثنا`);
  }
  const kb = [
    [{ text: "🔄 همگام‌سازی با پنل", callback_data: `ndsync:${idx}` }],
    [{ text: m.enabled === false ? "▶️ فعال‌سازی هشدار" : "⏸ توقف هشدار", callback_data: `ndtg:${idx}` }],
    [{ text: "🔗 وب‌هوک", callback_data: `ndhook:${idx}` }, { text: "🧪 هشدار آزمایشی", callback_data: `ndtest:${idx}` }],
    ...nodeButtonRows(idx, m, st),
    [{ text: "🗑 حذف", callback_data: `nddel:${idx}` }],
    [{ text: "🔙 بازگشت", callback_data: "nd" }],
  ];
  await edit(lines.join("\n"), kb);
}

async function handleNodeEvent(token, payload, env, botToken) {
  const kv = env.BOT_KV;
  if (!kv) return;
  try {
    const monitors = await getNodeMonitors(kv);
    const m = monitors.find((x) => x.token === token);
    if (!m) return;
    const nodeName = String(payload.node || payload.name || "").trim();
    if (!nodeName) return;
    const panels = await getPanels(kv);
    const panel = panels.find((p) => p.id === m.panel_id);
    const rawStatus = String(payload.status || "").toLowerCase();
    const rawEvent = String(payload.event || "").toLowerCase();
    const reason = payload.reason || payload.message || payload.error || "";
    let dir = null;
    if (
      ["down", "disconnect", "disconnected", "offline", "stopped", "node_down"].includes(rawEvent) ||
      NODE_OFF_STATES.includes(rawStatus)
    ) {
      dir = "down";
    } else if (
      ["up", "connect", "connected", "online", "running", "node_up"].includes(rawEvent) ||
      NODE_DOWN_STATES.includes(rawStatus)
    ) {
      dir = "up";
    }
    if (!dir) return;
    const st = await getNodeState(kv, m.id);
    const cur = st.nodes[nodeName];
    if (cur && cur.status === dir) return;
    st.nodes[nodeName] = {
      name: nodeName,
      status: dir,
      reason: reason ? String(reason) : null,
      ts: new Date().toISOString(),
      first_seen: (cur && cur.first_seen) || new Date().toISOString(),
    };
    st.ts = st.nodes[nodeName].ts;
    await saveNodeState(kv, m.id, st);
    if (m.enabled === false) return;
    if ((m.excluded || []).includes(nodeName)) return;
    const admins = await getAdmins(kv, env);
    const panelName = (panel && panel.name) || m.name;
    const ts = ndFmtTs(st.nodes[nodeName].ts);
    const msg =
      (dir === "down"
        ? `🚨 نود قطع شد!\n🖥 پنل: ${escHtml(panelName)}\n🖧 نود: ${code(nodeName)}\n⏱ زمان: ${ts} به وقت ایران\n🔎 علت: ${reason ? escHtml(String(reason)) : "—"}`
        : `✅ نود وصل شد!\n🖥 پنل: ${escHtml(panelName)}\n🖧 نود: ${code(nodeName)}\n⏱ زمان: ${ts} به وقت ایران${reason ? `\nℹ️ ${escHtml(String(reason))}` : ""}`);
    for (const a of admins) await sendPanelMsg(botToken, a, msg);
  } catch (e) {
    console.error("NDHOOK", e && e.stack ? e.stack : String(e));
  }
}

function duplicateLabels(records, zoneName) {
  const counts = {};
  for (const r of records) counts[r.name] = (counts[r.name] || 0) + 1;
  const seen = {};
  const out = {};
  for (const r of records) {
    let label = recordLabel(r, zoneName);
    if (counts[r.name] > 1) {
      seen[r.name] = (seen[r.name] || 0) + 1;
      label = `${seen[r.name]}. ${label}`;
    }
    out[r.id] = label;
  }
  return out;
}

function maskToken(t) {
  if (!t) return "";
  if (t.length <= 12) return t.slice(0, 6) + "…";
  return t.slice(0, 10) + "…" + t.slice(-4);
}

const ZONE_PAGE_SIZE = 16;

async function showZones(page, filter, accounts, send, kv, chatId) {
  const all = await getAllZones(accounts, kv);
  if (all.length === 0) {
    await send("☁️ کلودفلر\n\n📭 هیچ دامنه‌ای یافت نشد.\nیک اکانت کلودفلر با دسترسی Zone Read اضافه کنید یا دامنه جدید بسازید.", [
      [
        { text: "➕ افزودن دامنه جدید", callback_data: "addzone" },
        { text: "👤 افزودن اکانت کلودفلر", callback_data: "accadd" },
      ],
      [{ text: "🏠 منو", callback_data: "menu" }],
    ]);
    return;
  }

  const flt = filter === undefined ? "all" : String(filter);
  const zones = flt === "all" ? all : all.filter((z) => z._acc === Number(flt));

  const pages = Math.ceil(zones.length / ZONE_PAGE_SIZE);
  if (page < 0) page = 0;
  if (page >= pages) page = pages - 1;
  if (chatId) await kv.put(`zctx:${chatId}`, JSON.stringify({ filter: flt, page }), { expirationTtl: 86400 });

  const slice = zones.slice(page * ZONE_PAGE_SIZE, page * ZONE_PAGE_SIZE + ZONE_PAGE_SIZE);

  const keyboard = [];
  for (let i = 0; i < slice.length; i += 2) {
    const row = [];
    for (let j = i; j < i + 2; j++) {
      if (j < slice.length) {
        const z = slice[j];
        row.push({ text: `${z.status === "active" ? "🟢" : "⚪"} ${z.name}`, callback_data: `z:${z._acc}:${z.id}` });
      } else {
        row.push(EMPTY_BTN);
      }
    }
    keyboard.push(row);
  }

  keyboard.push([{ text: flt === "all" ? "📁 ✅ همه" : "📁 همه", callback_data: `zf:all:0` }]);

  for (let i = 0; i < accounts.length; i += 3) {
    const row = [];
    for (let j = i; j < i + 3; j++) {
      if (j < accounts.length) {
        const a = accounts[j];
        row.push({ text: flt === String(j) ? `👤 ✅ ${a.name}` : `👤 ${a.name}`, callback_data: `zf:${j}:0` });
      } else {
        row.push(EMPTY_BTN);
      }
    }
    keyboard.push(row);
  }

  keyboard.push([
    { text: "➕ افزودن دامنه جدید", callback_data: "addzone" },
    { text: "👤 افزودن اکانت کلودفلر", callback_data: "accadd" },
  ]);

  const nav = [];
  if (page > 0) nav.push({ text: "⬅️", callback_data: `zf:${flt}:${page - 1}` });
  else nav.push(EMPTY_BTN);
  nav.push({ text: "🔙 بازگشت", callback_data: "menu" });
  if (page < pages - 1) nav.push({ text: "➡️", callback_data: `zf:${flt}:${page + 1}` });
  else nav.push(EMPTY_BTN);
  keyboard.push(nav);

  const label = flt === "all" ? "همه اکانت‌ها" : (accounts[Number(flt)] ? accounts[Number(flt)].name : "؟");
  let title = `☁️ کلودفلر — ${label}`;
  if (pages > 1) title += ` — صفحه ${page + 1} از ${pages}`;
  await send(title, keyboard);
}

async function showRecords(zone, page, accounts, send, kv) {
  const records = await getRecords(zone, accounts, kv);
  const token = makeToken();
  await kv.put(
    `s:${token}`,
    JSON.stringify({ zone_id: zone.id, zone_name: zone.name, acc: zone._acc, page: page || 0, zback: "zones" }),
    { expirationTtl: 86400 }
  );

  if (records.length === 0) {
    const keyboard = [
      [{ text: "➕ افزودن", callback_data: `addz:${token}` }],
      [{ text: "⚙️ تنظیمات", callback_data: `zset:${token}` }],
      [{ text: "🔙 بازگشت", callback_data: "zones" }],
    ];
    await send(`📭 رکوردی برای ${zone.name} یافت نشد.`, keyboard);
    return;
  }

  await renderRecords(zone, records, token, page, send, undefined, "zones");
}

async function renderRecords(zone, records, token, page, send, selected, backCb) {
  const pages = Math.ceil(records.length / RECORD_PAGE_SIZE);
  if (page < 0) page = 0;
  if (page >= pages) page = pages - 1;

  const slice = records.slice(page * RECORD_PAGE_SIZE, page * RECORD_PAGE_SIZE + RECORD_PAGE_SIZE);
  const selSet = new Set(selected || []);
  const labels = duplicateLabels(records, zone.name);

  const keyboard = [];
  for (let i = 0; i < slice.length; i += 3) {
    const row = [];
    for (let j = i; j < i + 3; j++) {
      if (j < slice.length) {
        const r = slice[j];
        const mark = selSet.has(r.id) ? "✅" : "⬜";
        const cbData = selected !== undefined ? `sel:${token}:${r.id}` : `e:${token}:${r.id}`;
        row.push({ text: `${selected !== undefined ? mark + " " : ""}${labels[r.id]}`, callback_data: cbData });
      } else {
        row.push(EMPTY_BTN);
      }
    }
    keyboard.push(row);
  }

  if (selected !== undefined) {
    if (selSet.size > 0) {
      keyboard.push([
        { text: "🗑 حذف انتخاب‌ها", callback_data: `bulkdel:${token}` },
        { text: "✏️ تغییر مقدار", callback_data: `bulkedit:${token}` },
      ]);
      keyboard.push([
        { text: "🔄 تغییر نوع", callback_data: `bulktype:${token}` },
        { text: "❌ لغو انتخاب", callback_data: `seldone:${token}` },
      ]);
      keyboard.push([{ text: "⭐ افزودن به منتخب‌ها", callback_data: `favsel:${token}` }]);
    } else {
      keyboard.push([{ text: "❌ لغو انتخاب", callback_data: `seldone:${token}` }]);
    }
  } else {
    keyboard.push([
      { text: "⚙️ تنظیمات", callback_data: `zset:${token}` },
      { text: "🗂 گروهی", callback_data: `selmode:${token}` },
      { text: "➕ افزودن", callback_data: `addz:${token}` },
      { text: "🔍 جستجو", callback_data: `zsearch:${token}` },
    ]);
  }

  const nav = [];
  if (selected !== undefined) {
    nav.push(page > 0 ? { text: "◀️", callback_data: `selp:${token}:${page - 1}` } : EMPTY_BTN);
    nav.push({ text: `📄 ${page + 1}/${pages}`, callback_data: "noop" });
    nav.push(page < pages - 1 ? { text: "▶️", callback_data: `selp:${token}:${page + 1}` } : EMPTY_BTN);
  } else {
    nav.push(page > 0 ? { text: "◀️", callback_data: `p:${token}:${page - 1}` } : EMPTY_BTN);
    nav.push({ text: "🔙 بازگشت", callback_data: backCb || "zones" });
    nav.push(page < pages - 1 ? { text: "▶️", callback_data: `p:${token}:${page + 1}` } : EMPTY_BTN);
  }
  keyboard.push(nav);

  const title = selected !== undefined
    ? `🗂 ${zone.name} — ${selSet.size} انتخاب شده`
    : `📋 ${zone.name}` + (pages > 1 ? ` — صفحه ${page + 1} از ${pages}` : "");
  await send(title, keyboard);
}

async function showArvanDomains(page, arvanAccounts, edit, kv) {
  if (!arvanAccounts.length) {
    await edit("🇮🇷 آروان کلاد\n\n📭 اکانتی ثبت نشده. با دکمهٔ زیر اضافه کنید.", [
      [{ text: "➕ افزودن اکانت آروان", callback_data: "arvanaccadd" }],
      [{ text: "🏠 منو", callback_data: "menu" }],
    ]);
    return;
  }
  const items = [];
  let err = "";
  for (let i = 0; i < arvanAccounts.length; i++) {
    try {
      const domains = await arvanGetAllDomains(arvanAccounts[i].token);
      for (const d of domains) items.push({ domain: d.domain, acc: i, name: arvanAccounts[i].name });
    } catch (e) {
      err = e && e.message ? e.message : String(e);
    }
  }
  if (!items.length) {
    await edit(
      "🇮🇷 آروان کلاد\n\n📭 دامنه‌ای در اکانت‌های آروان پیدا نشد." +
        (err ? "\n⚠️ خطا: " + escHtml(err) : "") +
        "\n\nℹ️ ساخت دامنه در آروان از طریق API امکان‌پذیر نیست؛ باید از پنل آروان اضافه شود. پس از افزودن، دکمهٔ «🔄 همگام‌سازی» را بزن (سپس ساخت ساب‌دامنه/رکورد از همین ربات انجام می‌شود).",
      [
        [{ text: "➕ افزودن دامنه در پنل آروان", url: "https://my.arvancloud.ir/cdn/domains" }],
        [{ text: "🔄 همگام‌سازی", callback_data: "arvnsync" }],
        [{ text: "➕ افزودن اکانت", callback_data: "arvanaccadd" }, { text: "🏠 منو", callback_data: "menu" }],
      ]
    );
    return;
  }
  const per = CZ_PAGE_SIZE;
  const pages = Math.max(1, Math.ceil(items.length / per));
  if (page < 0) page = 0;
  if (page >= pages) page = pages - 1;
  const slice = items.slice(page * per, page * per + per);
  const lines = ["🇮🇷 آروان کلاد — دامنه‌ها (" + items.length + ")", ""];
  const kb = [];
  for (const it of slice) kb.push([{ text: `🔍 ${it.domain}`, callback_data: `arv:${it.acc}:${it.domain}` }]);
  if (pages > 1) {
    kb.push([
      { text: "⬅️", callback_data: `arvpage:${page - 1}` },
      { text: `${page + 1}/${pages}`, callback_data: "noop" },
      { text: "➡️", callback_data: `arvpage:${page + 1}` },
    ]);
  }
  kb.push([
    { text: "🔄 همگام‌سازی", callback_data: "arvnsync" },
    { text: "➕ افزودن اکانت", callback_data: "arvanaccadd" },
  ]);
  kb.push([{ text: "➕ افزودن دامنه در پنل آروان", url: "https://my.arvancloud.ir/cdn/domains" }]);
  kb.push([{ text: "🏠 منو", callback_data: "menu" }]);
  await edit(lines.join("\n"), kb);
}

async function showArvanRecords(domain, accIdx, token, arvanAccounts, edit, kv) {
  const token_val = arvanAccounts[accIdx].token;
  const records = await arvanGetAllRecords(token_val, domain);
  await kv.put(
    `s:${token}`,
    JSON.stringify({ domain, acc: accIdx, provider: "arvan" }),
    { expirationTtl: 86400 }
  );
  if (records.length === 0) {
    await edit(
      `📭 رکوردی برای ${domain} یافت نشد.`,
      [
        [{ text: "➕ افزودن", callback_data: `addz:${token}` }],
        [{ text: "🔙 بازگشت", callback_data: "arvan" }],
      ]
    );
    return;
  }
  await renderArvanRecords(domain, records, token, 0, edit);
}

async function renderArvanRecords(domain, records, token, page, edit, backCb) {
  const pages = Math.ceil(records.length / RECORD_PAGE_SIZE);
  if (page < 0) page = 0;
  if (page >= pages) page = pages - 1;
  const slice = records.slice(page * RECORD_PAGE_SIZE, page * RECORD_PAGE_SIZE + RECORD_PAGE_SIZE);
  const labels = {};
  const counts = {};
  for (const r of records) {
    counts[r.name] = (counts[r.name] || 0) + 1;
  }
  const seen = {};
  for (const r of records) {
    if (counts[r.name] > 1) {
      seen[r.name] = (seen[r.name] || 0) + 1;
      labels[r.id] = `${seen[r.name]}. ${r.type}-${r.name}`;
    } else {
      labels[r.id] = `${r.type}-${r.name}`;
    }
  }
  const keyboard = [];
  for (let i = 0; i < slice.length; i += 3) {
    const row = [];
    for (let j = i; j < i + 3; j++) {
      if (j < slice.length) {
        const r = slice[j];
        row.push({ text: labels[r.id], callback_data: `e:${token}:${r.id}` });
      } else {
        row.push(EMPTY_BTN);
      }
    }
    keyboard.push(row);
  }
  keyboard.push([
    { text: "➕ افزودن", callback_data: `addz:${token}` },
    { text: "🔍 جستجو", callback_data: `zsearch:${token}` },
  ]);
  const nav = [];
  nav.push(page > 0 ? { text: "◀️", callback_data: `ap:${token}:${page - 1}` } : EMPTY_BTN);
  nav.push({ text: "🔙 بازگشت", callback_data: backCb || "arvan" });
  nav.push(page < pages - 1 ? { text: "▶️", callback_data: `ap:${token}:${page + 1}` } : EMPTY_BTN);
  keyboard.push(nav);
  await edit(`📋 ${domain} — صفحه ${page + 1} از ${pages}`, keyboard);
}

async function renderSettingsGroup(token, session, accounts, edit, title, keys) {
  const zone = await getZoneById(session.zone_id, session.acc, accounts);
  const map = await getSettingsMap(zone, accounts);
  const buttons = [];
  for (const k of keys) {
    const info = SETTINGS_INFO[k];
    const cur = map[k];
    if (info.type === "bool") {
      const on = cur === "on";
      buttons.push({ text: `${on ? "✅" : "❌"} ${info.label}`, callback_data: `ztog:${token}:${k}` });
    } else {
      buttons.push({ text: `🔧 ${info.label}: ${info.values[cur] || cur}`, callback_data: `zval:${token}:${k}` });
    }
  }
  const keyboard = grid2(buttons);
  keyboard.push([{ text: "⬅️ بازگشت", callback_data: `zset:${token}` }]);
  await edit(`${title} — ${zone.name}:\n\nبرای تغییر روی هر گزینه کلیک کنید:`, keyboard);
}

async function renderAdmins(admins, mainAdmin, send) {
  let text = "👥 ادمین‌های ربات:\n\n";
  admins.forEach((id, i) => {
    text += `${i + 1}) ${id}${id === mainAdmin ? " — 👑 اصلی" : ""}\n`;
  });
  const keyboard = [
    [{ text: "➕ افزودن ادمین", callback_data: "adminadd" }],
    [{ text: "🗑 حذف ادمین", callback_data: "admindel" }],
    [{ text: "🏠 منو", callback_data: "menu" }],
  ];
  await send(text, keyboard);
}

async function showAccounts(accounts, arvanAccounts, send) {
  let text = "";
  const keyboard = [];
  if (accounts.length > 0) {
    text += "👤 اکانت‌های کلودفلر:\n\n";
    accounts.forEach((a, i) => {
      text += `${i + 1}) ${a.name}\n   توکن: ${maskToken(a.token)}\n\n`;
    });
  } else {
    text += "👤 کلودفلر: هیچ اکانتی ثبت نشده\n\n";
  }
  if (arvanAccounts.length > 0) {
    text += "🇮🇷 اکانت‌های آروان کلاد:\n\n";
    arvanAccounts.forEach((a, i) => {
      text += `${i + 1}) ${a.name}\n   کلید: ${maskArvanToken(a.token)}\n\n`;
    });
  } else {
    text += "🇮🇷 آروان کلاد: هیچ اکانتی ثبت نشده\n\n";
  }
  keyboard.push([{ text: "➕ افزودن اکانت کلودفلر", callback_data: "accadd" }]);
  keyboard.push([{ text: "➕ افزودن اکانت آروان", callback_data: "arvanaccadd" }]);
  if (accounts.length > 0 || arvanAccounts.length > 0) {
    keyboard.push([{ text: "🗑 حذف اکانت", callback_data: "accdel" }]);
  }
  keyboard.push([{ text: "🏠 منو", callback_data: "menu" }]);
  await send(text, keyboard);
}

async function handleAdd(args, accounts, send, kv) {
  const [, zoneName, type, name, content, ttlArg, proxyArg] = args;
  if (!zoneName || !type || !name || !content) {
    await send("⚠️ استفاده: /add <دامنه> <نوع> <نام> <مقدار> [ttl] [proxy]\nمثال: /add example.com A www 1.2.3.4 true");
    return;
  }
  const typeUp = type.toUpperCase();
  if (!RECORD_TYPES.includes(typeUp)) {
    await send("❌ نوع رکورد باید A، AAAA یا CNAME باشد.");
    return;
  }
  const zone = await findZone(zoneName, accounts);
  if (!zone) return send("❌ دامنه پیدا نشد.");

  const ttl = ttlArg ? Number(ttlArg) : 1;
  const proxied = proxyArg ? proxyArg.toLowerCase() === "true" : false;
  const fullName = normalizeName(name, zone.name);

  const res = await fetch(`${CF_API}/zones/${zone.id}/dns_records`, {
    method: "POST",
    headers: hdr(accounts[zone._acc].token),
    body: JSON.stringify({ type: typeUp, name: fullName, content, ttl: ttl || 1, proxied }),
  });
  const data = await res.json();
  if (data.success) {
    await invalidateCache(kv, zone.id);
    await send(
      `✅ رکورد ساخته شد:\n${data.result.type}-${code(data.result.name)} → ${code(data.result.content)}\nTTL: خودکار | Proxy: ${data.result.proxied ? "روشن" : "خاموش"}`,
      [[{ text: "⬅️ دامنه‌ها", callback_data: "zones" }, { text: "🏠 منو", callback_data: "menu" }]]
    );
  } else {
    await send("❌ خطا از کلودفلر:\n" + cfErrText(data));
  }
}

async function findRecord(zone, type, name, accounts) {
  const fullName = normalizeName(name, zone.name);
  const res = await fetch(
    `${CF_API}/zones/${zone.id}/dns_records?type=${type.toUpperCase()}&name=${encodeURIComponent(fullName)}`,
    { headers: hdr(accounts[zone._acc].token) }
  );
  const data = await res.json();
  if (!data.success || !data.result || data.result.length === 0) return null;
  return data.result[0];
}

async function handleEdit(args, accounts, send, kv) {
  const [, zoneName, type, name, content] = args;
  if (!zoneName || !type || !name || !content) {
    await send("⚠️ استفاده: /edit <دامنه> <نوع> <نام> <مقدار جدید>");
    return;
  }
  const zone = await findZone(zoneName, accounts);
  if (!zone) return send("❌ دامنه پیدا نشد.");
  const record = await findRecord(zone, type, name, accounts);
  if (!record) return send("❌ رکورد پیدا نشد.");

  const res = await fetch(`${CF_API}/zones/${zone.id}/dns_records/${record.id}`, {
    method: "PATCH",
    headers: hdr(accounts[zone._acc].token),
    body: JSON.stringify({ content }),
  });
  const data = await res.json();
  if (data.success) {
    await invalidateCache(kv, zone.id);
    await send(`✅ مقدار ${code(record.name)} به ${code(content)} تغییر کرد.`);
  } else {
    await send("❌ خطا:\n" + cfErrText(data));
  }
}

async function handleSetTtl(args, accounts, send, kv) {
  const [, zoneName, type, name, ttlArg] = args;
  if (!zoneName || !type || !name || !ttlArg) {
    await send("⚠️ استفاده: /setttl <دامنه> <نوع> <نام> <ttl>\n(ttl=1 یعنی خودکار)");
    return;
  }
  const zone = await findZone(zoneName, accounts);
  if (!zone) return send("❌ دامنه پیدا نشد.");
  const record = await findRecord(zone, type, name, accounts);
  if (!record) return send("❌ رکورد پیدا نشد.");

  const ttl = Number(ttlArg);
  const res = await fetch(`${CF_API}/zones/${zone.id}/dns_records/${record.id}`, {
    method: "PATCH",
    headers: hdr(accounts[zone._acc].token),
    body: JSON.stringify({ ttl: ttl || 1 }),
  });
  const data = await res.json();
  if (data.success) {
    await invalidateCache(kv, zone.id);
    await send(`✅ TTL رکورد ${code(record.name)} به ${data.result.ttl === 1 ? "خودکار" : data.result.ttl} تغییر کرد.`);
  } else {
    await send("❌ خطا:\n" + cfErrText(data));
  }
}

async function handleToggleProxy(args, accounts, send, kv) {
  const [, zoneName, type, name] = args;
  if (!zoneName || !type || !name) {
    await send("⚠️ استفاده: /toggleproxy <دامنه> <نوع> <نام>");
    return;
  }
  const zone = await findZone(zoneName, accounts);
  if (!zone) return send("❌ دامنه پیدا نشد.");
  const record = await findRecord(zone, type, name, accounts);
  if (!record) return send("❌ رکورد پیدا نشد.");

  const res = await fetch(`${CF_API}/zones/${zone.id}/dns_records/${record.id}`, {
    method: "PATCH",
    headers: hdr(accounts[zone._acc].token),
    body: JSON.stringify({ proxied: !record.proxied }),
  });
  const data = await res.json();
  if (data.success) {
    await invalidateCache(kv, zone.id);
    await send(`✅ Proxy رکورد ${code(record.name)} ${data.result.proxied ? "روشن" : "خاموش"} شد.`);
  } else {
    await send("❌ خطا:\n" + cfErrText(data));
  }
}

async function handleDelete(args, accounts, send, kv) {
  const [, zoneName, type, name] = args;
  if (!zoneName || !type || !name) {
    await send("⚠️ استفاده: /delete <دامنه> <نوع> <نام>");
    return;
  }
  const zone = await findZone(zoneName, accounts);
  if (!zone) return send("❌ دامنه پیدا نشد.");
  const record = await findRecord(zone, type, name, accounts);
  if (!record) return send("❌ رکورد پیدا نشد.");

  const del = await fetch(`${CF_API}/zones/${zone.id}/dns_records/${record.id}`, {
    method: "DELETE",
    headers: hdr(accounts[zone._acc].token),
  });
  const delData = await del.json();
  if (delData.success) {
    await invalidateCache(kv, zone.id);
    await send(`✅ رکورد ${record.type}-${code(record.name)} حذف شد.`);
  } else {
    await send("❌ خطا در حذف:\n" + cfErrText(delData));
  }
}

async function searchRecords(accounts, field, query, zoneFilter, kv) {
  const results = [];
  const zones = zoneFilter ? [zoneFilter] : await getAllZones(accounts, kv);
  const q = query.toLowerCase();
  for (const zone of zones) {
    const records = await getRecords(zone, accounts, kv);
    for (const r of records) {
      const hay = (field === "name" ? r.name : r.content) || "";
      if (hay.toLowerCase().includes(q)) {
        results.push({ acc: zone._acc, zone_id: zone.id, zone_name: zone.name, record: r });
      }
    }
  }
  return results;
}

async function renderSearchResults(token, results, query, field, send) {
  if (results.length === 0) {
    await send(`🔍 نتیجه‌ای برای «${query}» پیدا نشد.`, [
      [{ text: "🔍 جستجوی جدید", callback_data: "search" }, { text: "🏠 منو", callback_data: "menu" }],
    ]);
    return;
  }
  const slice = results.slice(0, PAGE_SIZE);
  let text = `🔍 نتایج جستجوی «${escHtml(query)}» (${results.length} مورد):\n\n`;
  slice.forEach((res, i) => {
    text +=
      `${i + 1}) ${res.record.type}-${code(res.record.name)}\n` +
      `   → ${code(res.record.content)}\n` +
      `   دامنه: ${code(res.zone_name)}\n\n`;
  });

  const keyboard = slice.map((res, i) => [
    { text: `✏️ ${res.record.type}-${res.record.name}`, callback_data: `se:${token}:${i}` },
    { text: "🗑", callback_data: `sd:${token}:${i}` },
  ]);
  keyboard.push([{ text: "🔍 جستجوی جدید", callback_data: "search" }, { text: "🏠 منو", callback_data: "menu" }]);
  await send(text, keyboard);
}

async function addRecordFromPending(pending, content, accounts, kv, chatId, send) {
  await kv.delete(`pend:${chatId}`);
  if (pending.provider === "arvan") {
    const domain = pending.domain;
    const acc = { token: await arvanToken(kv, pending.acc) };
    const res = await arvanCreateRecord(acc.token, domain, pending.rtype, pending.name, content, false);
    if (res.success !== false) {
      await send(
        `✅ رکورد ساخته شد:\n${pending.rtype}-${pending.name} → ${code(content)}\n${domain}`,
        [[{ text: "🇮🇷 آروان", callback_data: "arvan" }, { text: "🏠 منو", callback_data: "menu" }]]
      );
    } else {
      await send("❌ خطا:\n" + cfErrText(res));
    }
    return;
  }
  const fullName = normalizeName(pending.name, pending.zone_name);
  const res = await fetch(`${CF_API}/zones/${pending.zone_id}/dns_records`, {
    method: "POST",
    headers: hdr(accounts[pending.acc].token),
    body: JSON.stringify({ type: pending.rtype, name: fullName, content, ttl: 1, proxied: false }),
  });
  const data = await res.json();
  if (data.success) {
    await invalidateCache(kv, pending.zone_id);
    await send(
      `✅ رکورد ساخته شد:\n${data.result.type}-${code(data.result.name)} → ${code(data.result.content)}\nTTL: خودکار`,
      [[{ text: "⬅️ دامنه‌ها", callback_data: "zones" }, { text: "🏠 منو", callback_data: "menu" }]]
    );
  } else {
    await send("❌ خطا:\n" + cfErrText(data));
  }
}

async function cnameTargetPickerData(accounts, kv, name, page = 0) {
  const zones = await getAllZones(accounts, kv);
  const pages = Math.ceil(zones.length / CZ_PAGE_SIZE);
  if (page < 0) page = 0;
  if (page >= pages) page = pages - 1;
  const slice = zones.slice(page * CZ_PAGE_SIZE, page * CZ_PAGE_SIZE + CZ_PAGE_SIZE);
  const kb = grid2(
    slice.map((z) => ({ text: `📁 ${z.name}`, callback_data: `cz:${z._acc}:${z.id}` }))
  );
  const nav = [];
  nav.push(page > 0 ? { text: "◀️", callback_data: `czp:${name}:${page - 1}` } : EMPTY_BTN);
  nav.push({ text: `📄 ${page + 1}/${pages}`, callback_data: "noop" });
  nav.push(page < pages - 1 ? { text: "▶️", callback_data: `czp:${name}:${page + 1}` } : EMPTY_BTN);
  kb.push(nav);
  kb.push([{ text: "⌨️ ورود دستی دامنه", callback_data: "czman" }]);
  kb.push([{ text: "🏠 منو", callback_data: "menu" }]);
  return {
    text: `🔤 نام «${code(name)}» ثبت شد.\n\nبرای مقدار CNAME:\n• یک دامنه را انتخاب کنید تا ساب‌دامنه‌هایش را ببینید\n• یا مقدار را مستقیم تایپ کنید:`,
    kb,
  };
}

async function resolvePending(pending, value, chatId, accounts, arvanAccounts, send, kv, botToken) {
  const type = pending.type;
  const txt = value.trim();

  if (type === "hf_gptoken") {
    await kv.delete(`pend:${chatId}`);
    const cfg = await getHostFilterCfg(kv);
    cfg.gpToken = txt === "-" ? "" : txt;
    await saveHostFilterCfg(kv, cfg);
    await send(cfg.gpToken ? "✅ توکن Globalping ذخیره شد." : "🗑 توکن Globalping حذف شد.", [[{ text: "⚙️ تنظیمات", callback_data: "hfset" }]]);
    return;
  }

  if (type === "hf_set") {
    await kv.delete(`pend:${chatId}`);
    const key = pending.key;
    const cfg = await getHostFilterCfg(kv);
    const n = Number(txt);
    const limits = { interval: [1, 1440], cities: [1, cfg.citiesSel.length], maxok: [0, 3], probes: [1, 50], minfail: [1, 50], batch: [1, 60], maxchanges: [1, 20], backupkeep: [1, 10] };
    const lim = limits[key];
    if (!lim || !Number.isInteger(n) || n < lim[0] || n > lim[1]) {
      await send("❌ مقدار نامعتبر است (بازه: " + (lim ? lim[0] + " تا " + lim[1] : "?") + ").", [[{ text: "🔙 تنظیمات", callback_data: "hfset" }]]);
      return;
    }
    if (key === "interval") cfg.intervalMin = n;
    else if (key === "cities") cfg.cities = Math.min(n, cfg.citiesSel.length);
    else if (key === "maxok") cfg.maxOk = n;
    else if (key === "probes") cfg.probes = n;
    else if (key === "minfail") cfg.minFail = n;
    else if (key === "batch") cfg.batch = n;
    else if (key === "maxchanges") cfg.maxChanges = n;
    else if (key === "backupkeep") cfg.backupKeep = n;
    await saveHostFilterCfg(kv, cfg);
    await send("✅ ذخیره شد.", [[{ text: "⚙️ تنظیمات", callback_data: "hfset" }]]);
    return;
  }

  if (type === "admin_add") {
    await kv.delete(`pend:${chatId}`);
    const id = Number(txt);
    if (!Number.isInteger(id) || id <= 0) {
      await send("❌ شناسه عددی معتبر نیست. دوباره از منوی ادمین‌ها تلاش کنید.");
      return;
    }
    let list = (await kv.get("admins", "json")) || [];
    list = list.map(Number);
    if (!list.includes(id)) list.push(id);
    await kvPutCached(kv, "admins", JSON.stringify(list));
    await send(`✅ ادمین ${id} اضافه شد.`, [
      [{ text: "👥 ادمین‌ها", callback_data: "admins_menu" }, { text: "🏠 منو", callback_data: "menu" }],
    ]);
    return;
  }

  if (type === "addzone_name") {
    await kv.delete(`pend:${chatId}`);
    const name = txt.toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(name)) {
      await send("❌ نام دامنه معتبر نیست. دوباره از منو تلاش کنید.");
      return;
    }
    const acc = accounts[pending.acc];
    if (!acc) return send("❌ اکانت پیدا نشد.");
    const accountId = await getAccountId(accounts, pending.acc);
    if (!accountId) return send("❌ نمی‌توان شناسه اکانت را پیدا کرد. مطمئن شوید اکانت حداقل یک دامنه دارد.");
    const res = await fetch(`${CF_API}/zones`, {
      method: "POST",
      headers: hdr(acc.token),
      body: JSON.stringify({ name, account: { id: accountId }, type: "full" }),
    });
    const data = await res.json();
    if (data.success) {
      await invalidateCache(kv, null);
      await send(
        `✅ دامنه «${name}» با موفقیت در اکانت «${acc.name}» ثبت شد!\n\n` +
        `برای فعال‌سازی، این NS ها را در رجیسترار دامنه تنظیم کنید:\n${(data.result.name_servers || []).join("\n")}`,
        [[{ text: "📋 دامنه‌ها", callback_data: "zones" }, { text: "🏠 منو", callback_data: "menu" }]]
      );
    } else {
      await send("❌ خطا در ثبت دامنه:\n" + cfErrText(data));
    }
    return;
  }

  if (type === "bulk_edit") {
    await kv.delete(`pend:${chatId}`);
    let okCount = 0;
    for (const id of pending.ids) {
      const res = await fetch(`${CF_API}/zones/${pending.zone_id}/dns_records/${id}`, {
        method: "PATCH",
        headers: hdr(accounts[pending.acc].token),
        body: JSON.stringify({ content: txt }),
      });
      const d = await res.json();
      if (d.success) okCount++;
    }
    await invalidateCache(kv, pending.zone_id);
    await kv.delete(`sel:${chatId}`);
    const summary = `✅ تغییر یافت\n\nمقدار ${okCount} از ${pending.ids.length} رکورد با موفقیت به:\n${code(txt)}\nبه‌روزرسانی شد.`;
    if (pending.msgId) {
      await editMessage(botToken, chatId, pending.msgId, summary, []);
      await sleep(2000);
      await redrawRecordsList(kv, accounts, botToken, chatId, pending.msgId, pending.token, 0);
    } else {
      await send(summary, [
        [{ text: "📋 دامنه‌ها", callback_data: "zones" }, { text: "🏠 منو", callback_data: "menu" }],
      ]);
    }
    return;
  }

  if (type === "bulk_type") {
    await kv.delete(`pend:${chatId}`);
    let okCount = 0;
    for (const id of pending.ids) {
      const res = await fetch(`${CF_API}/zones/${pending.zone_id}/dns_records/${id}`, {
        method: "PATCH",
        headers: hdr(accounts[pending.acc].token),
        body: JSON.stringify({ type: pending.new_type, content: txt, ttl: 1 }),
      });
      const d = await res.json();
      if (d.success) okCount++;
    }
    await invalidateCache(kv, pending.zone_id);
    await kv.delete(`sel:${chatId}`);
    const summary = `✅ تغییر یافت\n\nنوع ${okCount} از ${pending.ids.length} رکورد به ${pending.new_type} تغییر کرد.`;
    if (pending.msgId) {
      await editMessage(botToken, chatId, pending.msgId, summary, []);
      await sleep(2000);
      await redrawRecordsList(kv, accounts, botToken, chatId, pending.msgId, pending.token, 0);
    } else {
      await send(summary, [
        [{ text: "📋 دامنه‌ها", callback_data: "zones" }, { text: "🏠 منو", callback_data: "menu" }],
      ]);
    }
    return;
  }

  if (type === "acc_name") {
    if (!txt) return send("⚠️ نام معتبری وارد کنید.");
    await kv.put(`pend:${chatId}`, JSON.stringify({ type: "acc_token", name: txt }), { expirationTtl: 600 });
    await send(`🔑 حالا API Token اکانت «${txt}» را بفرستید:`);
    return;
  }

  if (type === "acc_token") {
    await kv.delete(`pend:${chatId}`);
    const token = txt;
    const res = await fetch(`${CF_API}/zones?per_page=1`, { headers: hdr(token) });
    const data = await res.json();
    if (!data.success) {
      await send("❌ توکن نامعتبر است یا دسترسی Zone Read ندارد.", mainMenuKeyboard());
      return;
    }
    accounts.push({ name: pending.name, token });
    await kvPutCached(kv, "accounts", JSON.stringify(accounts));
    await invalidateCache(kv, null);
    await send(`✅ اکانت «${pending.name}» اضافه شد.`, [
      [{ text: "👤 اکانت‌ها", callback_data: "accounts" }, { text: "📋 دامنه‌ها", callback_data: "zones" }],
    ]);
    return;
  }

  if (type === "arvan_acc_name") {
    if (!txt) return send("⚠️ نام معتبری وارد کنید.");
    await kv.put(`pend:${chatId}`, JSON.stringify({ type: "arvan_acc_token", name: txt }), { expirationTtl: 600 });
    await send(`🔑 حالا API Key اکانت آروان «${txt}» را بفرستید:`);
    return;
  }

  if (type === "arvan_acc_token") {
    await kv.delete(`pend:${chatId}`);
    const token = txt;
    arvanAccounts.push({ name: pending.name, token });
    await kvPutCached(kv, "arvan_accounts", JSON.stringify(arvanAccounts));
    await send(`✅ اکانت آروان «${pending.name}» اضافه شد.\n\n⚠️ در صورت خطا، کلید از تنظیمات اصلاح شود.`, [
      [{ text: "👤 اکانت‌ها", callback_data: "accounts" }, { text: "🇮🇷 آروان", callback_data: "arvan" }],
    ]);
    return;
  }

  if (type === "ar_name") {
    if (!txt) return send("⚠️ نام رکورد معتبر نیست.");
    await kv.put(
      `pend:${chatId}`,
      JSON.stringify({ ...pending, type: "ar_content", name: txt }),
      { expirationTtl: 600 }
    );
    if (pending.rtype === "CNAME") {
      const { text, kb } = await cnameTargetPickerData(accounts, kv, txt);
      await send(text, kb);
    } else {
      await send("🔤 حالا مقدار IP رکورد را بفرستید:");
    }
    return;
  }

  if (type === "ar_content") {
    await addRecordFromPending(pending, txt, arvanAccounts, kv, chatId, send);
    return;
  }

  if (type === "edit_value" || type === "edit_ttl") {
    await kv.delete(`pend:${chatId}`);
    if (pending.provider === "arvan") {
      const records = await arvanGetAllRecords(arvanAccounts[pending.acc].token, pending.domain);
      const prev = records.find((r) => r.id === pending.record_id);
      if (!prev) {
        await send("❌ رکورد پیدا نشد.");
        return;
      }
      if (type === "edit_ttl") {
        await send("⚠️ تغییر TTL در آروان کلاد به صورت مستقیم پشتیبانی نمی‌شود.");
        return;
      }
      prev.content = txt;
      const res = await arvanUpdateRecord(arvanAccounts[pending.acc].token, pending.domain, prev, txt);
      if (res.success !== false) {
        const summary = diffSummary(prev.name, prev.content, txt);
        if (pending.msgId) {
          await editMessage(botToken, chatId, pending.msgId, summary, []);
          await sleep(2000);
          await redrawRecordDetailNav(kv, accounts, botToken, chatId, pending.msgId);
        } else {
          await send(summary, [[{ text: "🇮🇷 آروان", callback_data: "arvan" }, { text: "🏠 منو", callback_data: "menu" }]]);
        }
      } else {
        await send("❌ خطا:\n" + cfErrText(res));
      }
      return;
    }
    const prev = await getRecordById(pending.acc, pending.zone_id, pending.record_id, accounts);
    const body = {};
    if (type === "edit_ttl") body.ttl = Number(txt) || 1;
    else {
      body.content = txt;
      if (pending.type === "edit_value" && prev) {
        const isIp = isIpv4(txt) || isIpv6(txt);
        if (prev.type === "A" && !isIp) {
          await fetch(`${CF_API}/zones/${pending.zone_id}/dns_records/${pending.record_id}`, {
            method: "DELETE",
            headers: hdr(accounts[pending.acc].token),
            signal: withTimeout(),
          });
          const newRes = await fetch(`${CF_API}/zones/${pending.zone_id}/dns_records`, {
            method: "POST",
            headers: hdr(accounts[pending.acc].token),
            body: JSON.stringify({ type: "CNAME", name: prev.name, content: txt, ttl: 1, proxied: prev.proxied || false }),
            signal: withTimeout(),
          });
          const newData = await newRes.json();
          if (newData.success) {
            await invalidateCache(kv, pending.zone_id);
            if (pending.msgId) {
              await editMessage(botToken, chatId, pending.msgId, `🔄 تبدیل شد\n${code(prev.name)}\n🔴 قبلاً: ${code(prev.content)} (A)\n🟢 الان: ${code(txt)} (CNAME)`, []);
              await sleep(2000);
              if (pending.srToken) await redrawSearchResultsNav(kv, accounts, botToken, chatId, pending.msgId, pending.srToken);
              else await redrawRecordDetailNav(kv, accounts, botToken, chatId, pending.msgId);
            } else {
              await send(`🔄 تبدیل شد\n${code(prev.name)}\n🔴 قبلاً: ${code(prev.content)} (A)\n🟢 الان: ${code(txt)} (CNAME)`, [[{ text: "⬅️ دامنه‌ها", callback_data: "zones" }, { text: "🏠 منو", callback_data: "menu" }]]);
            }
            return;
          } else {
            await send("❌ خطا در ساخت رکورد CNAME:\n" + cfErrText(newData));
            return;
          }
        } else if (prev.type === "CNAME" && isIp) {
          await fetch(`${CF_API}/zones/${pending.zone_id}/dns_records/${pending.record_id}`, {
            method: "DELETE",
            headers: hdr(accounts[pending.acc].token),
            signal: withTimeout(),
          });
          const newRes = await fetch(`${CF_API}/zones/${pending.zone_id}/dns_records`, {
            method: "POST",
            headers: hdr(accounts[pending.acc].token),
            body: JSON.stringify({ type: "A", name: prev.name, content: txt, ttl: 1, proxied: false }),
            signal: withTimeout(),
          });
          const newData = await newRes.json();
          if (newData.success) {
            await invalidateCache(kv, pending.zone_id);
            if (pending.msgId) {
              await editMessage(botToken, chatId, pending.msgId, `🔄 تبدیل شد\n${code(prev.name)}\n🔴 قبلاً: ${code(prev.content)} (CNAME)\n🟢 الان: ${code(txt)} (A)`, []);
              await sleep(2000);
              if (pending.srToken) await redrawSearchResultsNav(kv, accounts, botToken, chatId, pending.msgId, pending.srToken);
              else await redrawRecordDetailNav(kv, accounts, botToken, chatId, pending.msgId);
            } else {
              await send(`🔄 تبدیل شد\n${code(prev.name)}\n🔴 قبلاً: ${code(prev.content)} (CNAME)\n🟢 الان: ${code(txt)} (A)`, [[{ text: "⬅️ دامنه‌ها", callback_data: "zones" }, { text: "🏠 منو", callback_data: "menu" }]]);
            }
            return;
          } else {
            await send("❌ خطا در ساخت رکورد A:\n" + cfErrText(newData));
            return;
          }
        }
      }
    }

    const res = await fetch(`${CF_API}/zones/${pending.zone_id}/dns_records/${pending.record_id}`, {
      method: "PATCH",
      headers: hdr(accounts[pending.acc].token),
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (data.success) {
      await invalidateCache(kv, pending.zone_id);
      const r = data.result;
      if (pending.srToken) {
        const sr = await kv.get(`sr:${pending.srToken}`, "json");
        if (sr && Array.isArray(sr.results)) {
          for (const it of sr.results) {
            if (it.zone_id === pending.zone_id && it.record && it.record.id === pending.record_id) {
              it.record.content = data.result.content;
              it.record.type = data.result.type;
              it.record.ttl = data.result.ttl;
              it.record.proxied = data.result.proxied;
            }
          }
          await kv.put(`sr:${pending.srToken}`, JSON.stringify(sr), { expirationTtl: 3600 });
        }
      }
      let summary;
      if (type === "edit_ttl") {        const pv = prev && prev.ttl ? (prev.ttl === 1 ? "خودکار" : String(prev.ttl)) : "—";
        const nv = r.ttl === 1 ? "خودکار" : String(r.ttl);
        summary = `✅ تغییر یافت\n\n📛 ساب‌دامین: ${code(r.name)}\n\n🔴 TTL قبلی:\n${code(pv)}\n\n🟢 TTL فعلی:\n${code(nv)}`;
      } else {
        summary = diffSummary(r.name, prev && prev.content ? prev.content : "—", r.content);
      }
      if (pending.msgId) {
        await editMessage(botToken, chatId, pending.msgId, summary, []);
        await sleep(2000);
        if (pending.srToken) await redrawSearchResultsNav(kv, accounts, botToken, chatId, pending.msgId, pending.srToken);
        else await redrawRecordDetailNav(kv, accounts, botToken, chatId, pending.msgId);
      } else {
        await send(summary, [[{ text: "⬅️ دامنه‌ها", callback_data: "zones" }, { text: "🏠 منو", callback_data: "menu" }]]);
      }
    } else {
      await send("❌ خطا:\n" + cfErrText(data));
    }
    return;
  }

  if (type === "change_type") {
    const prev = await getRecordById(pending.acc, pending.zone_id, pending.record_id, accounts);
    await kv.delete(`pend:${chatId}`);
    const res = await fetch(`${CF_API}/zones/${pending.zone_id}/dns_records/${pending.record_id}`, {
      method: "PATCH",
      headers: hdr(accounts[pending.acc].token),
      body: JSON.stringify({ type: pending.new_type, content: txt, ttl: 1 }),
    });
    const data = await res.json();
    if (data.success) {
      await invalidateCache(kv, pending.zone_id);
      const r = data.result;
      if (pending.srToken) {
        const sr = await kv.get(`sr:${pending.srToken}`, "json");
        if (sr && Array.isArray(sr.results)) {
          for (const it of sr.results) {
            if (it.zone_id === pending.zone_id && it.record && it.record.id === pending.record_id) {
              it.record.content = data.result.content;
              it.record.type = data.result.type;
              it.record.ttl = data.result.ttl;
              it.record.proxied = data.result.proxied;
            }
          }
          await kv.put(`sr:${pending.srToken}`, JSON.stringify(sr), { expirationTtl: 3600 });
        }
      }
      const summary =
        `✅ تغییر یافت\n\n📛 ساب‌دامین: ${code(r.name)}\n\n` +
        `🔴 قبلی (${prev ? prev.type : "?"}):\n${code(prev ? prev.content : "—")}\n\n` +
        `🟢 فعلی (${r.type}):\n${code(r.content)}`;
      if (pending.msgId) {
        await editMessage(botToken, chatId, pending.msgId, summary, []);
        await sleep(2000);
        if (pending.srToken) await redrawSearchResultsNav(kv, accounts, botToken, chatId, pending.msgId, pending.srToken);
        else await redrawRecordDetailNav(kv, accounts, botToken, chatId, pending.msgId);
      } else {
        await send(summary, [[{ text: "⬅️ دامنه‌ها", callback_data: "zones" }, { text: "🏠 منو", callback_data: "menu" }]]);
      }
    } else {
      await send("❌ خطا:\n" + cfErrText(data));
    }
    return;
  }

  if (type === "bulk_del") {
    await kv.delete(`pend:${chatId}`);
    let okCount = 0;
    for (const id of pending.ids) {
      const del = await fetch(`${CF_API}/zones/${pending.zone_id}/dns_records/${id}`, {
        method: "DELETE",
        headers: hdr(accounts[pending.acc].token),
        signal: withTimeout(),
      });
      const d = await del.json();
      if (d.success) okCount++;
    }
    await invalidateCache(kv, pending.zone_id);
    await kv.delete(`sel:${chatId}`);
    await send(`✅ ${okCount} از ${pending.ids.length} رکورد حذف شد.`, [[{ text: "🗂 عملیات گروهی", callback_data: "bulk_main" }, { text: "🏠 منو", callback_data: "menu" }]]);
    return;
  }

  if (type === "bulk_edit") {
    await kv.delete(`pend:${chatId}`);
    let okCount = 0;
    for (const id of pending.ids) {
      const res = await fetch(`${CF_API}/zones/${pending.zone_id}/dns_records/${id}`, {
        method: "PATCH",
        headers: hdr(accounts[pending.acc].token),
        body: JSON.stringify({ content: txt }),
      });
      const d = await res.json();
      if (d.success) okCount++;
    }
    await invalidateCache(kv, pending.zone_id);
    await kv.delete(`sel:${chatId}`);
    await send(`✅ ${okCount} از ${pending.ids.length} رکورد به مقدار جدید تغییر کرد.`, [[{ text: "🗂 عملیات گروهی", callback_data: "bulk_main" }, { text: "🏠 منو", callback_data: "menu" }]]);
    return;
  }

  if (type === "bulk_type") {
    await kv.delete(`pend:${chatId}`);
    let okCount = 0;
    for (const id of pending.ids) {
      const res = await fetch(`${CF_API}/zones/${pending.zone_id}/dns_records/${id}`, {
        method: "PATCH",
        headers: hdr(accounts[pending.acc].token),
        body: JSON.stringify({ type: pending.new_type, content: txt, ttl: 1 }),
      });
      const d = await res.json();
      if (d.success) okCount++;
    }
    await invalidateCache(kv, pending.zone_id);
    await kv.delete(`sel:${chatId}`);
    await send(`✅ ${okCount} از ${pending.ids.length} رکورد به نوع ${pending.new_type} تغییر کرد.`, [[{ text: "🗂 عملیات گروهی", callback_data: "bulk_main" }, { text: "🏠 منو", callback_data: "menu" }]]);
    return;
  }

  if (type === "bulk_type_convert") {
    await kv.delete(`pend:${chatId}`);
    let okCount = 0;
    for (const id of pending.ids) {
      const res = await fetch(`${CF_API}/zones/${pending.zone_id}/dns_records/${id}`, {
        method: "PATCH",
        headers: hdr(accounts[pending.acc].token),
        body: JSON.stringify({ type: pending.new_type, content: txt, ttl: 1 }),
      });
      const d = await res.json();
      if (d.success) okCount++;
    }
    await invalidateCache(kv, pending.zone_id);
    await kv.delete(`sel:${chatId}`);
    await send(`✅ ${okCount} از ${pending.ids.length} رکورد به نوع ${pending.new_type} تغییر کرد.`, [[{ text: "🗂 عملیات گروهی", callback_data: "bulk_main" }, { text: "🏠 منو", callback_data: "menu" }]]);
    return;
  }

  if (type === "qa_search") {
    await kv.delete(`pend:${chatId}`);
    if (isIpLike(txt.trim())) {
      await kv.put(`qa:${chatId}`, JSON.stringify({ ip: txt.trim() }), { expirationTtl: 3600 });
      await sendQuickIpMenu(chatId, txt.trim(), kv, accounts, send);
      return;
    }
    const qa = await kv.get(`qa:${chatId}`, "json");
    await quickNameSearch(txt.trim(), qa && qa.ip ? qa : null, chatId, accounts, send, kv);
    return;
  }

  if (type === "qa_value") {
    await kv.delete(`pend:${chatId}`);
    const ip = txt.trim();
    if (!isIpLike(ip)) {
      if (pending.msgId) {
        await editMessage(botToken, chatId, pending.msgId, "❌ این مقدار IP نیست. یک IPv4 یا IPv6 معتبر بفرستید:", [[{ text: "❌ لغو", callback_data: "qacancel" }]]);
      } else {
        await send("❌ این مقدار IP نیست. یک IPv4 یا IPv6 معتبر بفرستید.");
      }
      return;
    }
    await kv.put(
      `qa:${chatId}`,
      JSON.stringify({ ip, zone_id: pending.zone_id, zone_name: pending.zone_name, acc: pending.acc, record_id: pending.record_id }),
      { expirationTtl: 3600 }
    );
    if (pending.msgId) {
      await showQaConfirm({ kv, chatId, messageId: pending.msgId, accounts, botToken, edit: (t, kb) => editMessage(botToken, chatId, pending.msgId, t, kb) });
    } else {
      const rec = await getRecordById(pending.acc, pending.zone_id, pending.record_id, accounts);
      await send(
        `⚡ ${code(rec ? rec.name : "؟")} — ${code(rec ? rec.content : "؟")} → ${code(ip)}\n\n` +
          `برای تأیید، /cancel بزنید یا دوباره IP را بفرستید.`,
        [[{ text: "✅ تأیید", callback_data: "qaok" }, { text: "❌ لغو", callback_data: "qacancel" }]]
      );
    }
    return;
  }

  if (type === "search") {
    await kv.delete(`pend:${chatId}`);
    const results = await searchRecords(accounts, pending.field, txt, null, kv);
    const token = makeToken();
    await kv.put(
      `sr:${token}`,
      JSON.stringify({ field: pending.field, query: txt, results }),
      { expirationTtl: 3600 }
    );
    await renderSearchResults(token, results, txt, pending.field, send);
    return;
  }

  if (type === "search_zone") {
    await kv.delete(`pend:${chatId}`);
    let results = [];
    if (pending.provider === "arvan") {
      const records = await arvanGetAllRecords(await arvanToken(kv, pending.acc), pending.domain);
      const q = txt.toLowerCase();
      for (const r of records) {
        const hay = pending.field === "name" ? r.name : r.content;
        if (hay.toLowerCase().includes(q)) {
          results.push({ zone_id: "arvan:" + pending.domain, zone_name: pending.domain, record: r, acc: pending.acc, provider: "arvan", domain: pending.domain });
        }
      }
    } else {
      const zone = await getZoneById(pending.zone_id, pending.acc, accounts);
      results = await searchRecords(accounts, pending.field, txt, zone, kv);
      for (const r of results) {
        r.provider = "cloudflare";
      }
    }
    const token = makeToken();
    await kv.put(
      `sr:${token}`,
      JSON.stringify({ field: pending.field, query: txt, results }),
      { expirationTtl: 3600 }
    );
    await renderSearchResults(token, results, txt, pending.field, send);
    return;
  }

  if (type === "p_name") {
    if (!txt) return send("⚠️ نام معتبری وارد کنید.");
    await kv.put(`pend:${chatId}`, JSON.stringify({ type: "p_url", name: txt }), { expirationTtl: 600 });
    await send("🌐 آدرس پنل را بفرستید (مثلاً https://phonepanel.ir):");
    return;
  }

  if (type === "p_url") {
    const url = txt.replace(/\/+$/, "");
    if (!/^https?:\/\//.test(url)) return send("❌ آدرس باید با http:// یا https:// شروع شود. دوباره بفرستید:");
    await kv.put(`pend:${chatId}`, JSON.stringify({ type: "p_user", name: pending.name, url }), { expirationTtl: 600 });
    await send("👤 نام‌کاربری ادمین پنل را بفرستید:");
    return;
  }

  if (type === "p_user") {
    if (!txt) return send("⚠️ نام‌کاربری معتبر وارد کنید.");
    await kv.put(`pend:${chatId}`, JSON.stringify({ type: "p_pass", name: pending.name, url: pending.url, username: txt }), { expirationTtl: 600 });
    await send("🔑 رمز عبور ادمین پنل را بفرستید (این پیام از چت حذف نمی‌شود ولی فقط در KV ذخیره می‌شود):");
    return;
  }

  if (type === "p_pass") {
    await kv.delete(`pend:${chatId}`);
    const panels = await getPanels(kv);
    panels.push({ id: makeToken(), name: pending.name, url: pending.url, username: pending.username, password: txt, enabled: true, last_error: null });
    await savePanels(kv, panels);
    await send(`✅ پنل «${pending.name}» ثبت شد.`, [
      [{ text: "🖥 مانیتور نود پاسارگارد", callback_data: "nd" }, { text: "🏠 منو", callback_data: "menu" }],
    ]);
    return;
  }

  // ===================== SSL Monitor =====================
  if (type === "ssl_host") {
    const host = txt.toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(host)) {
      await send("❌ نام دامنه معتبر نیست. دوباره بفرستید:");
      return;
    }
    await kv.put(`pend:${chatId}`, JSON.stringify({ type: "ssl_thr", host }), { expirationTtl: 600 });
    await send(`🔐 «${host}» ثبت شد.\n\nچند روز قبل از انقضا هشدار بدهم؟ (پیش‌فرض ۵ — یک عدد بفرستید):`);
    return;
  }

  if (type === "ssl_thr") {
    await kv.delete(`pend:${chatId}`);
    let threshold = Number(txt);
    if (!Number.isInteger(threshold) || threshold <= 0) threshold = 5;
    const monitors = await getSslMonitors(kv);
    if (monitors.some((m) => m.host === pending.host)) {
      await send("❌ این دامنه از قبل در نظارت است.", [[{ text: "🔐 مانیتور SSL", callback_data: "sslm" }]]);
      return;
    }
    monitors.push({ host: pending.host, port: 443, threshold });
    await saveSslMonitors(kv, monitors);
    await send(`✅ «${pending.host}» با آستانه ${threshold} روز به نظارت اضافه شد.`, [
      [{ text: "🔐 مانیتور SSL", callback_data: "sslm" }, { text: "🏠 منو", callback_data: "menu" }],
    ]);
    return;
  }

  // ===================== Hetzner =====================
  if (type === "hz_add_name") {
    if (!txt) return send("⚠️ نام معتبری وارد کنید.");
    await kv.put(`pend:${chatId}`, JSON.stringify({ type: "hz_add_token", name: txt }), { expirationTtl: 600 });
    await send(`🔑 حالا API Token هتزنر اکانت «${txt}» را بفرستید:`);
    return;
  }

  if (type === "hz_add_token") {
    await kv.delete(`pend:${chatId}`);
    const token = txt;
    const test = await hzFetch(token, "/datacenters?per_page=1");
    if (test.error) {
      await send("❌ توکن نامعتبر است.", [[{ text: "🇩🇪 هتزنر", callback_data: "hz" }, { text: "🏠 منو", callback_data: "menu" }]]);
      return;
    }
    const hzAccounts = await getHzAccounts(kv);
    hzAccounts.push({ name: pending.name, token });
    await saveHzAccounts(kv, hzAccounts);
    await send(`✅ اکانت «${pending.name}» اضافه شد.`, [
      [{ text: "🇩🇪 هتزنر", callback_data: "hz" }, { text: "🏠 منو", callback_data: "menu" }],
    ]);
    return;
  }

  if (type === "hz_srv_remark") {
    const remark = txt;
    if (/\s/.test(remark)) {
      await send("⚠️ نام سرور نباید فاصله داشته باشد. دوباره بفرستید:");
      return;
    }
    const hzAccounts = await getHzAccounts(kv);
    const acc = hzAccounts[pending.acc];
    if (!acc) {
      await send("❌ اکانت پیدا نشد.");
      await kv.delete(`pend:${chatId}`);
      return;
    }
    const dcs = await hzGetAll(acc.token, "/datacenters");
    if (!dcs.length) {
      await send("❌ دیتاسنتری پیدا نشد.");
      await kv.delete(`pend:${chatId}`);
      return;
    }
    await kv.put(`pend:${chatId}`, JSON.stringify({ type: "hz_srv_remark", acc: pending.acc, remark }), { expirationTtl: 600 });
    const kb = grid2(dcs.map((d) => ({ text: d.name, callback_data: `hzscd:${pending.acc}:${d.id}` })));
    kb.push([{ text: "🔙 انصراف", callback_data: `hzs:${pending.acc}:0` }]);
    await send("🌍 دیتاسنتر را انتخاب کنید:", kb);
    return;
  }

  if (type === "hz_srv_rename") {
    await kv.delete(`pend:${chatId}`);
    const hzAccounts = await getHzAccounts(kv);
    const acc = hzAccounts[pending.acc];
    const r = await hzFetch(acc.token, `/servers/${pending.server_id}`, { method: "PUT", body: JSON.stringify({ name: txt }) });
    if (r.error) {
      await send("❌ خطا: " + (r.error.message || ""));
      return;
    }
    await send("✅ نام سرور تغییر کرد.", [[{ text: "🖥️ سرورها", callback_data: `hzs:${pending.acc}:0` }]]);
    return;
  }

  if (type === "hz_ip_remark") {
    const hzAccounts = await getHzAccounts(kv);
    const acc = hzAccounts[pending.acc];
    if (!acc) {
      await send("❌ اکانت پیدا نشد.");
      await kv.delete(`pend:${chatId}`);
      return;
    }
    const dcs = await hzGetAll(acc.token, "/datacenters");
    if (!dcs.length) {
      await send("❌ دیتاسنتری پیدا نشد.");
      await kv.delete(`pend:${chatId}`);
      return;
    }
    await kv.put(`pend:${chatId}`, JSON.stringify({ type: "hz_ip_remark", acc: pending.acc, ip_type: pending.ip_type, remark: txt }), { expirationTtl: 600 });
    const kb = grid2(dcs.map((d) => ({ text: d.name, callback_data: `hzpcd:${pending.acc}:${d.id}` })));
    kb.push([{ text: "🔙 انصراف", callback_data: `hzp:${pending.acc}:0` }]);
    await send("🌍 دیتاسنتر را انتخاب کنید:", kb);
    return;
  }

  if (type === "hz_ip_rename") {
    await kv.delete(`pend:${chatId}`);
    const hzAccounts = await getHzAccounts(kv);
    const acc = hzAccounts[pending.acc];
    const r = await hzFetch(acc.token, `/primary_ips/${pending.ip_id}`, { method: "PUT", body: JSON.stringify({ name: txt }) });
    if (r.error) {
      await send("❌ خطا: " + (r.error.message || ""));
      return;
    }
    await send("✅ نام آی‌پی تغییر کرد.", [[{ text: "🌐 آی‌پی‌ها", callback_data: `hzp:${pending.acc}:0` }]]);
    return;
  }

  if (type === "hz_snap_remark") {
    const hzAccounts = await getHzAccounts(kv);
    const acc = hzAccounts[pending.acc];
    if (!acc) {
      await send("❌ اکانت پیدا نشد.");
      await kv.delete(`pend:${chatId}`);
      return;
    }
    const servers = await hzGetAll(acc.token, "/servers");
    if (!servers.length) {
      await send("❌ سروری پیدا نشد.");
      await kv.delete(`pend:${chatId}`);
      return;
    }
    await kv.put(`pend:${chatId}`, JSON.stringify({ type: "hz_snap_remark", acc: pending.acc, remark: txt }), { expirationTtl: 600 });
    const kb = grid2(servers.map((s) => ({ text: s.name, callback_data: `hzns:${pending.acc}:${s.id}` })));
    kb.push([{ text: "🔙 انصراف", callback_data: `hzn:${pending.acc}:0` }]);
    await send("🌍 سرور مبدا اسنپ‌شات را انتخاب کنید:", kb);
    return;
  }

  if (type === "hz_snap_rename") {
    await kv.delete(`pend:${chatId}`);
    const hzAccounts = await getHzAccounts(kv);
    const acc = hzAccounts[pending.acc];
    const r = await hzFetch(acc.token, `/images/${pending.image_id}`, { method: "PUT", body: JSON.stringify({ description: txt }) });
    if (r.error) {
      await send("❌ خطا: " + (r.error.message || ""));
      return;
    }
    await send("✅ نام اسنپ‌شات تغییر کرد.", [[{ text: "📸 اسنپ‌شات‌ها", callback_data: `hzn:${pending.acc}:0` }]]);
    return;
  }

  if (type === "ln_add_name") {
    if (!txt) return send("⚠️ نام معتبری وارد کنید.");
    await kv.put(`pend:${chatId}`, JSON.stringify({ type: "ln_add_token", name: txt }), { expirationTtl: 600 });
    await send(`🔑 حالا API Token لینود اکانت «${txt}» را بفرستید:`);
    return;
  }

  if (type === "ln_add_token") {
    await kv.delete(`pend:${chatId}`);
    const token = txt;
    const accTest = await lnFetch(token, "/account");
    if (accTest.errors || (!accTest.email && !accTest.company && !accTest.id)) {
      await send("❌ توکن نامعتبر است.", [[{ text: "🟢 لینود", callback_data: "ln" }, { text: "🏠 منو", callback_data: "menu" }]]);
      return;
    }
    const lnAccounts = await getLnAccounts(kv);
    lnAccounts.push({ name: pending.name, token });
    await saveLnAccounts(kv, lnAccounts);
    await send(`✅ اکانت «${pending.name}» اضافه شد.`, [
      [{ text: "🟢 لینود", callback_data: "ln" }, { text: "🏠 منو", callback_data: "menu" }],
    ]);
    return;
  }

  if (type === "ln_srv_remark") {
    const remark = txt;
    if (/\s/.test(remark)) {
      await send("⚠️ نام سرور نباید فاصله داشته باشد. دوباره بفرستید:");
      return;
    }
    const lnAccounts = await getLnAccounts(kv);
    const acc = lnAccounts[pending.acc];
    if (!acc) {
      await send("❌ اکانت پیدا نشد.");
      await kv.delete(`pend:${chatId}`);
      return;
    }
    const regions = (await lnGetAll(acc.token, "/regions")).filter((r) => (r.capabilities || []).includes("Linodes"));
    if (!regions.length) {
      await send("❌ منطقه‌ای پیدا نشد.");
      await kv.delete(`pend:${chatId}`);
      return;
    }
    await kv.put(`pend:${chatId}`, JSON.stringify({ type: "ln_srv_remark", acc: pending.acc, remark }), { expirationTtl: 600 });
    const kb = grid2(regions.map((r) => ({ text: r.label, callback_data: `lnscd:${pending.acc}:${r.id}` })));
    kb.push([{ text: "🔙 انصراف", callback_data: `lns:${pending.acc}:0` }]);
    await send("🌍 منطقه را انتخاب کنید:", kb);
    return;
  }

  if (type === "ln_srv_rename") {
    await kv.delete(`pend:${chatId}`);
    const lnAccounts = await getLnAccounts(kv);
    const acc = lnAccounts[pending.acc];
    const r = await lnFetch(acc.token, `/linode/instances/${pending.server_id}`, { method: "PUT", body: JSON.stringify({ label: txt }) });
    if (r.errors) {
      await send("❌ خطا: " + lnErr(r));
      return;
    }
    await send("✅ نام سرور تغییر کرد.", [[{ text: "🖥️ سرورها", callback_data: `lns:${pending.acc}:0` }]]);
    return;
  }

  if (type === "ln_snap_remark") {
    const lnAccounts = await getLnAccounts(kv);
    const acc = lnAccounts[pending.acc];
    if (!acc) {
      await send("❌ اکانت پیدا نشد.");
      await kv.delete(`pend:${chatId}`);
      return;
    }
    const servers = await lnGetAll(acc.token, "/linode/instances");
    if (!servers.length) {
      await send("❌ سروری پیدا نشد.");
      await kv.delete(`pend:${chatId}`);
      return;
    }
    await kv.put(`pend:${chatId}`, JSON.stringify({ type: "ln_snap_remark", acc: pending.acc, remark: txt }), { expirationTtl: 600 });
    const kb = grid2(servers.map((s) => ({ text: s.label, callback_data: `lnns:${pending.acc}:${s.id}` })));
    kb.push([{ text: "🔙 انصراف", callback_data: `lnn:${pending.acc}:0` }]);
    await send("🌍 سرور مبدا اسنپ‌شات را انتخاب کنید:", kb);
    return;
  }

  if (type === "ln_snap_rename") {
    await kv.delete(`pend:${chatId}`);
    const lnAccounts = await getLnAccounts(kv);
    const acc = lnAccounts[pending.acc];
    const r = await lnFetch(acc.token, `/images/${pending.image_id}`, { method: "PUT", body: JSON.stringify({ label: txt }) });
    if (r.errors) {
      await send("❌ خطا: " + lnErr(r));
      return;
    }
    await send("✅ نام اسنپ‌شات تغییر کرد.", [[{ text: "📸 اسنپ‌شات‌ها", callback_data: `lnn:${pending.acc}:0` }]]);
    return;
  }

  if (type === "ln_ip_rename") {
    await kv.delete(`pend:${chatId}`);
    const lnAccounts = await getLnAccounts(kv);
    const acc = lnAccounts[pending.acc];
    const r = await lnFetch(acc.token, `/networking/ips/${encodeURIComponent(pending.address)}`, { method: "PUT", body: JSON.stringify({ rdns: txt }) });
    if (r.errors) {
      await send("❌ خطا: " + lnErr(r));
      return;
    }
    await send("✅ رکورد PTR آی‌پی تغییر کرد.", [[{ text: "🌐 آی‌پی‌ها", callback_data: `lnp:${pending.acc}:0` }]]);
    return;
  }

  if (type === "rem_text") {
    if (!txt) {
      await send("⚠️ متن خالی است. دوباره بفرستید:");
      return;
    }
    await kv.put(`pend:${chatId}`, JSON.stringify({ type: "rem_when", target: pending.target || null, text: txt }), { expirationTtl: 900 });
    await send(REM_WHEN_TEXT, remWhenKb());
    return;
  }

  if (type === "rem_when") {
    const s = parseFaNums(txt).trim();
    const m = s.match(/^(\d{4})[\/\-.](\d{1,2})[\/\-.](\d{1,2})(?:[\s\-T]+(\d{1,2}):(\d{2}))$/);
    if (!m) {
      await send("❌ قالب درست نیست. مثال: 1404/06/20 14:30");
      return;
    }
    const jy = Number(m[1]);
    const jm = Number(m[2]);
    const jd = Number(m[3]);
    const hh = Number(m[4]);
    const mm = Number(m[5]);
    if (jm < 1 || jm > 12 || jd < 1 || jd > 31 || hh > 23 || mm > 59) {
      await send("❌ تاریخ/ساعت نامعتبر است. دوباره بفرستید:");
      return;
    }
    let at;
    try {
      at = jalaliToEpoch(jy, jm, jd, hh, mm);
    } catch (e) {
      await send("❌ تاریخ نامعتبر است. دوباره بفرستید:");
      return;
    }
    await finalizeReminder(kv, chatId, pending, at, send);
    return;
  }

  if (type === "rem_rel_num") {
    const n = Number(parseFaNums(txt).trim());
    if (!Number.isInteger(n) || n < 1 || n > 10000) {
      await send("❌ عدد نامعتبر است. یک عدد بین ۱ تا ۱۰۰۰۰ بفرستید:");
      return;
    }
    const at = addRel(pending.unit, n);
    await finalizeReminder(kv, chatId, pending, at, send);
    return;
  }

  if (type === "rem_abs_day") {
    const n = Number(parseFaNums(txt).trim());
    if (!Number.isInteger(n) || n < 1 || n > 31) {
      await send("❌ روز نامعتبر است. عددی بین ۱ تا ۳۱ بفرستید:");
      return;
    }
    let ok = false;
    try {
      const g = toGregorian(pending.jy, pending.jm, n);
      const b = toJalaali(g.gy, g.gm, g.gd);
      ok = b.jy === pending.jy && b.jm === pending.jm && b.jd === n;
    } catch (e) {}
    if (!ok) {
      await send("❌ این روز در آن ماه وجود ندارد. دوباره بفرستید:");
      return;
    }
    await kv.put(
      `pend:${chatId}`,
      JSON.stringify({ type: "rem_abs_time", target: pending.target || null, text: pending.text || "", jy: pending.jy, jm: pending.jm, jd: n, mode: pending.mode || "" }),
      { expirationTtl: 900 }
    );
    await send("🕒 ساعت را وارد کنید (مثلاً 14:30):", [[{ text: "🔙 بازگشت", callback_data: "remabs" }]]);
    return;
  }

  if (type === "rem_abs_time") {
    const m = parseFaNums(txt).trim().match(/^(\d{1,2}):(\d{2})$/);
    if (!m) {
      await send("❌ فرمت ساعت درست نیست. مثال: 14:30");
      return;
    }
    const hh = Number(m[1]);
    const mm = Number(m[2]);
    if (hh > 23 || mm > 59) {
      await send("❌ ساعت نامعتبر است. دوباره بفرستید:");
      return;
    }
    let at;
    try {
      at = jalaliToEpoch(pending.jy, pending.jm, pending.jd, hh, mm);
    } catch (e) {
      await send("❌ تاریخ نامعتبر است.");
      return;
    }
    await finalizeReminder(kv, chatId, pending, at, send);
    return;
  }
}

async function handleCallback(cb, botToken, adminId, kv, env) {
  const chatId = cb.message ? cb.message.chat.id : null;
  const messageId = cb.message ? cb.message.message_id : null;
  let data = cb.data || "";

  await tg(botToken, "answerCallbackQuery", { callback_query_id: cb.id });

  if (!chatId) return;

  if (data === "noop") return;

  const applyPerm = async (text, kb) => {
    if (!text || text.indexOf(PERM_MARK) === -1) return { text, kb };
    const clean = text.split(PERM_MARK).join("");
    const rows = kb ? kb.slice() : [];
    const row = [];
    if (data) {
      try {
        await kv.put(`pretry:${chatId}`, data, { expirationTtl: 900 });
        await kv.put(`pback:${chatId}`, parentCb(data), { expirationTtl: 900 });
      } catch (e) {}
      row.push({ text: "🔄 بررسی مجدد", callback_data: "permretry" });
    }
    row.push({ text: "⬅️ بازگشت", callback_data: "permback" });
    rows.push(row);
    return { text: clean, kb: rows };
  };
  const edit = async (text, kb) => {
    const r = await applyPerm(text, kb);
    return editMessage(botToken, chatId, messageId, r.text, r.kb);
  };
  const send = async (text, kb) => {
    const r = await applyPerm(text, kb);
    return sendMessage(botToken, chatId, r.text, r.kb);
  };

  if (!kv) {
    await edit("⚠️ KV با نام BOT_KV لازم است.");
    return;
  }

  const accounts = await getAccounts(kv, env);
  const arvanAccounts = await getArvanAccounts(kv);
  const hzAccounts = await getHzAccounts(kv);
  const lnAccounts = await getLnAccounts(kv);
  const admins = await getAdmins(kv, env);
  if (!admins.includes(chatId)) return;

  const isMain = chatId === adminId;

  try {
    if (data === "permretry") {
      const prev = await kv.get(`pretry:${chatId}`);
      if (!prev) return edit("⏳ عملیات قبلی منقضی شد. دوباره از منو تلاش کن.");
      data = prev;
    } else if (data === "permback") {
      const back = await kv.get(`pback:${chatId}`);
      data = back || "menu";
    } else if (data === "permretrytxt") {
      const cmd = await kv.get(`pretrytxt:${chatId}`);
      if (!cmd) return edit("⏳ عملیات قبلی منقضی شد. دوباره تلاش کن.");
      await processUpdate({ message: { chat: { id: chatId }, text: cmd } }, env, botToken, adminId);
      return;
    }
    if (data === "menu") {
      await kv.delete(`qa:${chatId}`);
      await kv.delete(`pend:${chatId}`);
      await edit(mainMenuText(), mainMenuKeyboard());
    } else if (data === "help") {
      await edit(helpText(), helpKeyboard());
    } else if (data === "hqi") {
      await edit(HELP_GUIDE.hqi, helpGuideKb());
    } else if (data.startsWith("hg:")) {
      await edit(HELP_GUIDE[data.slice(3)] || "ℹ️ راهنمای این بخش موجود نیست.", helpGuideKb());
    } else if (data === "admins_menu") {
      if (!isMain) return edit("❌ فقط ادمین اصلی می‌تواند ادمین‌ها را مدیریت کند.");
      await renderAdmins(admins, adminId, edit);
    } else if (data === "adminadd") {
      if (!isMain) return edit("❌ فقط ادمین اصلی می‌تواند ادمین اضافه کند.");
      await kv.put(`pend:${chatId}`, JSON.stringify({ type: "admin_add" }), { expirationTtl: 600 });
      await edit("➕ شناسه عددی تلگرام ادمین جدید را بفرستید (می‌توانید با /myid در ربات خود ببینید):", [
        [{ text: "🏠 منو", callback_data: "menu" }],
      ]);
    } else if (data === "admindel") {
      if (!isMain) return edit("❌ فقط ادمین اصلی می‌تواند ادمین حذف کند.");
      const extra = admins.filter((id) => id !== adminId);
      if (extra.length === 0) return edit("📭 ادمین دیگری وجود ندارد.", [
        [{ text: "⬅️ بازگشت", callback_data: "admins_menu" }],
      ]);
      const kb = extra.map((id) => [{ text: `🗑 ${id}`, callback_data: `admindely:${id}` }]);
      kb.push([{ text: "⬅️ بازگشت", callback_data: "admins_menu" }]);
      await edit("🗑 کدام ادمین حذف شود؟ (ادمین اصلی قابل حذف نیست)", kb);
    } else if (data.startsWith("admindely:")) {
      if (!isMain) return edit("❌ فقط ادمین اصلی.");
      const id = Number(data.slice(10));
      let list = (await kv.get("admins", "json")) || [];
      list = list.map(Number).filter((x) => x !== id);
      await kvPutCached(kv, "admins", JSON.stringify(list));
      await renderAdmins(await getAdmins(kv, env), adminId, edit);
    } else if (data === "addzone") {
      await edit("🌐 افزودن دامنه جدید\n\nدامنه را در کدام اکانت کلودفلر ثبت کنید؟", [
        ...accounts.map((a, i) => [{ text: a.name, callback_data: `azacc:${i}` }]),
        [{ text: "🏠 منو", callback_data: "menu" }],
      ]);
    } else if (data.startsWith("azacc:")) {
      const i = Number(data.slice(6));
      const acc = accounts[i];
      if (!acc) return edit("❌ اکانت پیدا نشد.");
      await kv.put(`pend:${chatId}`, JSON.stringify({ type: "addzone_name", acc: i }), { expirationTtl: 600 });
      await edit(`🌐 نام دامنه جدید را بفرستید (مثلاً example.com) — در اکانت «${acc.name}» ثبت می‌شود:`, [
        [{ text: "🏠 منو", callback_data: "menu" }],
      ]);
    } else if (data === "zones") {
      await showZones(0, "all", accounts, edit, kv, chatId);
    } else if (data === "arvan") {
      await showArvanDomains(0, arvanAccounts, edit, kv);
    } else if (data.startsWith("arvacc:")) {
      await showArvanDomains(0, arvanAccounts, edit, kv);
    } else if (data === "arvnsync") {
      await kvDeleteCached(kv, "arvan:cached:domains");
      await edit("🔄 در حال همگام‌سازی با آروان...", [[{ text: "⏳ لطفا صبر کنید", callback_data: "noop" }]]);
      await showArvanDomains(0, arvanAccounts, edit, kv);
    } else if (data.startsWith("arvpage:")) {
      const page = Number(data.slice(10));
      await showArvanDomains(page, arvanAccounts, edit, kv);
    } else if (data.startsWith("arv:")) {
      const parts = data.split(":");
      const accIdx = Number(parts[1]);
      const domain = parts[2];
      const token = makeToken();
      await kv.put(`s:${token}`, JSON.stringify({ domain, acc: accIdx, provider: "arvan" }), { expirationTtl: 86400 });
      await showArvanRecords(domain, accIdx, token, arvanAccounts, edit, kv);
    } else if (data.startsWith("ap:")) {
      const parts = data.split(":");
      const token = parts[1];
      const page = Number(parts[2]);
      const session = await kv.get(`s:${token}`, "json");
      if (!session || session.provider !== "arvan") return edit("⏳ نشست منقضی شده.");
      session.page = page;
      await kv.put(`s:${token}`, JSON.stringify(session), { expirationTtl: 86400 });
      const records = await arvanGetAllRecords(arvanAccounts[session.acc].token, session.domain);
      await renderArvanRecords(session.domain, records, token, page, edit, "arvan");
    } else if (data.startsWith("zf:")) {
      const parts = data.split(":");
      const flt = parts[1];
      const page = Number(parts[2]) || 0;
      await showZones(page, flt, accounts, edit, kv, chatId);
    } else if (data === "search") {
      await edit("🔍 جستجوی رکورد\n\nبر اساس چه چیزی جستجو کنیم؟", [
        [{ text: "🔤 بر اساس نام/دامنه", callback_data: "sf:name" }],
        [{ text: "🌐 بر اساس IP/مقدار", callback_data: "sf:content" }],
        [{ text: "🏠 منو", callback_data: "menu" }],
      ]);
    } else if (data.startsWith("sf:")) {
      const field = data.slice(3);
      await kv.put(`pend:${chatId}`, JSON.stringify({ type: "search", field }), { expirationTtl: 600 });
      await edit(
        field === "name" ? "🔤 نام دامنه یا بخشی از آن را بفرستید:" : "🌐 IP یا بخشی از مقدار را بفرستید:",
        [[{ text: "🏠 منو", callback_data: "menu" }]]
      );
    } else if (data === "accounts") {
      await showAccounts(accounts, arvanAccounts, edit);
    } else if (data === "accadd") {
      await kv.put(`pend:${chatId}`, JSON.stringify({ type: "acc_name" }), { expirationTtl: 600 });
      await edit("👤 افزودن اکانت کلودفلر\n\nنام دلخواه اکانت را بفرستید (مثلاً: اصلی، بکاپ):", [
        [{ text: "🏠 منو", callback_data: "menu" }],
      ]);
    } else if (data === "accdel") {
      if (accounts.length === 0 && arvanAccounts.length === 0) return edit("📭 اکانتی نیست.", [[{ text: "🏠 منو", callback_data: "menu" }]]);
      const kb = [];
      for (let i = 0; i < accounts.length; i++) kb.push([{ text: `☁️ 🗑 ${accounts[i].name}`, callback_data: `dacc:${i}` }]);
      for (let i = 0; i < arvanAccounts.length; i++) kb.push([{ text: `🇮🇷 🗑 ${arvanAccounts[i].name}`, callback_data: `darvan:${i}` }]);
      kb.push([{ text: "⬅️ بازگشت", callback_data: "accounts" }]);
      await edit("🗑 کدام اکانت حذف شود؟", kb);
    } else if (data.startsWith("dacc:")) {
      const idx = Number(data.slice(5));
      const acc = accounts[idx];
      if (!acc) return edit("❌ اکانت پیدا نشد.", [[{ text: "⬅️ بازگشت", callback_data: "accounts" }]]);
      await edit(`⚠️ مطمئنید اکانت «${acc.name}» حذف شود؟\nتوکن: ${maskToken(acc.token)}`, [
        [{ text: "✅ بله", callback_data: `daccy:${idx}` }, { text: "❌ انصراف", callback_data: "accounts" }],
      ]);
    } else if (data.startsWith("daccy:")) {
      const idx = Number(data.slice(6));
      const acc = accounts[idx];
      if (!acc) return edit("❌ اکانت پیدا نشد.", [[{ text: "⬅️ بازگشت", callback_data: "accounts" }]]);
      accounts.splice(idx, 1);
      await kvPutCached(kv, "accounts", JSON.stringify(accounts));
      await edit(`✅ اکانت «${acc.name}» حذف شد.`, [
        [{ text: "👤 اکانت‌ها", callback_data: "accounts" }, { text: "🏠 منو", callback_data: "menu" }],
      ]);
    } else if (data === "arvanaccadd") {
      await kv.put(`pend:${chatId}`, JSON.stringify({ type: "arvan_acc_name" }), { expirationTtl: 600 });
      await edit("🇮🇷 افزودن اکانت آروان کلاد\n\nنام دلخواه اکانت را بفرستید (مثلاً: اصلی، بکاپ):", [
        [{ text: "🏠 منو", callback_data: "menu" }],
      ]);
    } else if (data === "arvanaccdel") {
      if (arvanAccounts.length === 0) return edit("📭 اکانتی نیست.", [[{ text: "🏠 منو", callback_data: "menu" }]]);
      const kb = arvanAccounts.map((a, i) => [{ text: `🗑 ${a.name}`, callback_data: `darvan:${i}` }]);
      kb.push([{ text: "⬅️ بازگشت", callback_data: "accounts" }]);
      await edit("🗑 کدام اکانت آروان حذف شود؟", kb);
    } else if (data.startsWith("darvan:")) {
      const idx = Number(data.slice(7));
      const acc = arvanAccounts[idx];
      if (!acc) return edit("❌ اکانت پیدا نشد.", [[{ text: "⬅️ بازگشت", callback_data: "accounts" }]]);
      await edit(`⚠️ مطمئنید اکانت «${acc.name}» حذف شود؟\nکلید: ${maskArvanToken(acc.token)}`, [
        [{ text: "✅ بله", callback_data: `darvany:${idx}` }, { text: "❌ انصراف", callback_data: "accounts" }],
      ]);
    } else if (data.startsWith("darvany:")) {
      const idx = Number(data.slice(9));
      const acc = arvanAccounts[idx];
      if (!acc) return edit("❌ اکانت پیدا نشد.", [[{ text: "⬅️ بازگشت", callback_data: "accounts" }]]);
      arvanAccounts.splice(idx, 1);
      await kvPutCached(kv, "arvan_accounts", JSON.stringify(arvanAccounts));
      await edit(`✅ اکانت «${acc.name}» حذف شد.`, [
        [{ text: "👤 اکانت‌ها", callback_data: "accounts" }, { text: "🏠 منو", callback_data: "menu" }],
      ]);
    } else if (data === "addrec") {
      const zones = await getAllZones(accounts, kv);
      const arvanDomains = [];
      for (let i = 0; i < arvanAccounts.length; i++) {
        const domains = await arvanGetAllDomains(arvanAccounts[i].token);
        for (const d of domains) {
          arvanDomains.push({ domain: d.domain, acc: i });
        }
      }
      const allItems = [];
      for (const z of zones) {
        allItems.push({ text: `${z.status === "active" ? "🟢" : "⚪"} ☁️ ${z.name}`, cb: `arz:${z._acc}:${z.id}` });
      }
      for (const d of arvanDomains) {
        allItems.push({ text: `🟢 🇮🇷 ${d.domain}`, cb: `arvrec:${d.acc}:${d.domain}` });
      }
      if (allItems.length === 0) return edit("📭 هیچ دامنه‌ای نیست.", [[{ text: "🏠 منو", callback_data: "menu" }]]);
      const kb = [];
      for (let i = 0; i < allItems.length; i += 2) {
        const row = [{ text: allItems[i].text, callback_data: allItems[i].cb }];
        if (i + 1 < allItems.length) row.push({ text: allItems[i + 1].text, callback_data: allItems[i + 1].cb });
        else row.push(EMPTY_BTN);
        kb.push(row);
      }
      kb.push([{ text: "🏠 منو", callback_data: "menu" }]);
      await edit("➕ روی دامنه‌ای که می‌خواهید رکورد بسازید کلیک کنید:", kb);
    } else if (data.startsWith("arvrec:")) {
      const parts = data.split(":");
      const accIndex = Number(parts[1]);
      const domain = parts[2];
      const token = makeToken();
      await kv.put(`s:${token}`, JSON.stringify({ domain, acc: accIndex, provider: "arvan" }), { expirationTtl: 86400 });
      await edit(`➕ ساخت رکورد در ${domain}\n\nنوع رکورد را انتخاب کنید:`, typeKeyboard(token, 0));
    } else if (data.startsWith("arz:")) {
      const parts = data.split(":");
      const accIndex = Number(parts[1]);
      const zoneId = parts[2];
      const zone = await getZoneById(zoneId, accIndex, accounts);
      if (!zone) return edit("❌ دامنه پیدا نشد.");
      const token = makeToken();
      await kv.put(`s:${token}`, JSON.stringify({ zone_id: zone.id, zone_name: zone.name, acc: accIndex }), {
        expirationTtl: 86400,
      });
      await edit(`➕ ساخت رکورد در ${zone.name}\n\nنوع رکورد را انتخاب کنید:`, typeKeyboard(token, 0));
    } else if (data.startsWith("addz:")) {
      const token = data.slice(5);
      const session = await kv.get(`s:${token}`, "json");
      if (!session) return edit("⏳ نشست منقضی شده.");
      if (session.provider === "arvan") {
        await edit(`➕ ساخت رکورد در ${session.domain}\n\nنوع رکورد را انتخاب کنید:`, typeKeyboard(token, 0));
      } else {
        const zone = await getZoneById(session.zone_id, session.acc, accounts);
        await edit(`➕ ساخت رکورد در ${zone.name}\n\nنوع رکورد را انتخاب کنید:`, typeKeyboard(token, 0));
      }
    } else if (data.startsWith("at:")) {
      const parts = data.split(":");
      const token = parts[1];
      const rtype = parts[2];
      const session = await kv.get(`s:${token}`, "json");
      if (!session) return edit("⏳ نشست منقضی شده.");
      await kv.put(
        `pend:${chatId}`,
        JSON.stringify({ type: "ar_name", acc: session.acc, zone_id: session.zone_id, zone_name: session.zone_name, rtype, provider: session.provider || "cloudflare", domain: session.domain }),
        { expirationTtl: 600 }
      );
      await edit(`➕ ساخت رکورد ${rtype}\n\nنام رکورد را بفرستید (مثلاً www یا @):`, [
        [{ text: "⬅️ انصراف", callback_data: `rback:${token}` }],
      ]);
    } else if (data === "czback") {
      const pending = await kv.get(`pend:${chatId}`, "json");
      if (!pending || pending.type !== "ar_content") return edit("⏳ عملیات منقضی شده.");
      const { text, kb } = await cnameTargetPickerData(accounts, kv, pending.name);
      await edit(text, kb);
    } else if (data.startsWith("cz:")) {
      const parts = data.split(":");
      const accIndex = Number(parts[1]);
      const zoneId = parts[2];
      let page = Number(parts[3]) || 0;
      const zone = await getZoneById(zoneId, accIndex, accounts);
      if (!zone) return edit("❌ دامنه پیدا نشد.");
      const records = await getRecords(zone, accounts, kv);
      const counts = {};
      for (const rec of records) counts[rec.name] = (counts[rec.name] || 0) + 1;
      const seen = {};
      const items = records.map((rec) => {
        let label = rec.name;
        if (counts[rec.name] > 1) {
          seen[rec.name] = (seen[rec.name] || 0) + 1;
          label = `${seen[rec.name]}. ${label}`;
        }
        return { text: `↪️ ${label}`, callback_data: `czr:${rec.name}` };
      });
      const pages = Math.ceil(items.length / CZR_PAGE_SIZE);
      if (page < 0) page = 0;
      if (page >= pages) page = pages - 1;
      const slice = items.slice(page * CZR_PAGE_SIZE, page * CZR_PAGE_SIZE + CZR_PAGE_SIZE);
      const kb = [];
      kb.push([{ text: `🏠 ${zone.name} (ریشه دامنه)`, callback_data: `czr:${zone.name}` }]);
      for (const row of grid2(slice)) kb.push(row);
      const nav = [];
      nav.push(page > 0 ? { text: "◀️", callback_data: `cz:${accIndex}:${zoneId}:${page - 1}` } : EMPTY_BTN);
      nav.push({ text: `📄 ${page + 1}/${pages}`, callback_data: "noop" });
      nav.push(page < pages - 1 ? { text: "▶️", callback_data: `cz:${accIndex}:${zoneId}:${page + 1}` } : EMPTY_BTN);
      kb.push(nav);
      kb.push([{ text: "⌨️ ورود دستی دامنه", callback_data: "czman" }]);
      kb.push([{ text: "⬅️ بازگشت", callback_data: "czback" }]);
      await edit(`🔤 ساب‌دامنه‌های «${zone.name}»:\n\nروی یکی کلیک کنید تا به‌عنوان هدف CNAME استفاده شود:`, kb);
    } else if (data.startsWith("czp:")) {
      const rest = data.slice(4);
      const idx = rest.lastIndexOf(":");
      const name = idx >= 0 ? rest.slice(0, idx) : rest;
      const page = idx >= 0 ? Number(rest.slice(idx + 1)) || 0 : 0;
      const { text, kb } = await cnameTargetPickerData(accounts, kv, name, page);
      await edit(text, kb);
    } else if (data === "czman") {
      const pending = await kv.get(`pend:${chatId}`, "json");
      if (!pending || pending.type !== "ar_content") return edit("⏳ عملیات منقضی شده.");
      await edit(`⌨️ دامنه هدف را به‌صورت دستی تایپ کنید (مثلاً target.example.com):`, [
        [{ text: "⬅️ انصراف", callback_data: "menu" }],
      ]);
    } else if (data.startsWith("czr:")) {
      const targetName = data.slice(4);
      const pending = await kv.get(`pend:${chatId}`, "json");
      if (!pending || pending.type !== "ar_content") return edit("⏳ عملیات منقضی شده.");
      await addRecordFromPending(pending, targetName, accounts, kv, chatId, edit);
    } else if (data.startsWith("zsearch:")) {
      const token = data.slice(8);
      const session = await kv.get(`s:${token}`, "json");
      if (!session) return edit("⏳ نشست منقضی شده.");
      const zoneName = session.provider === "arvan" ? session.domain : session.zone_name;
      await edit(`🔍 جستجو در ${zoneName}\n\nبر اساس چه چیزی جستجو کنیم؟`, [
        [{ text: "🔤 بر اساس نام/دامنه", callback_data: `zsf:${token}:name` }],
        [{ text: "🌐 بر اساس IP/مقدار", callback_data: `zsf:${token}:content` }],
        [{ text: "⬅️ بازگشت", callback_data: session.provider === "arvan" ? `rback:${token}` : `rback:${token}` }],
      ]);
    } else if (data.startsWith("zsf:")) {
      const parts = data.split(":");
      const token = parts[1];
      const field = parts[2];
      const session = await kv.get(`s:${token}`, "json");
      if (!session) return edit("⏳ نشست منقضی شده.");
      await kv.put(
        `pend:${chatId}`,
        JSON.stringify({ type: "search_zone", field, zone_id: session.zone_id, acc: session.acc, provider: session.provider || "cloudflare", domain: session.domain }),
        { expirationTtl: 600 }
      );
      await edit(
        field === "name" ? "🔤 نام یا بخشی از آن را بفرستید:" : "🌐 IP یا بخشی از مقدار را بفرستید:",
        [[{ text: "⬅️ انصراف", callback_data: session.provider === "arvan" ? `rback:${token}` : `rback:${token}` }]]
      );
    } else if (data.startsWith("zset:")) {
      const token = data.slice(5);
      const session = await kv.get(`s:${token}`, "json");
      if (!session) return edit("⏳ نشست منقضی شده.");
      const zone = await getZoneById(session.zone_id, session.acc, accounts);
      await edit(`⚙️ تنظیمات ${zone.name}:\n\nوضعیت: ${zone.status}`, [
        ...grid2([
          { text: "🔒 SSL / TLS", callback_data: `zssl:${token}` },
          { text: "🛡 امنیت", callback_data: `zsec:${token}` },
          { text: "⚡ کارایی", callback_data: `zperf:${token}` },
          { text: "ℹ️ جزئیات دامنه", callback_data: `zd:${token}` },
          { text: "🧹 پاکسازی کامل کش", callback_data: `zpurge:${token}` },
          { text: `🚧 حالت توسعه: ${zone.development_mode === 1 ? "روشن" : "خاموش"}`, callback_data: `zdev:${token}` },
          { text: zone.status === "active" ? "⏸️ توقف دامنه" : "▶️ فعال‌سازی دامنه", callback_data: `zpause:${token}` },
        ]),
        [{ text: "⬅️ بازگشت", callback_data: `rback:${token}` }],
      ]);
    } else if (data.startsWith("zssl:")) {
      const token = data.slice(5);
      const session = await kv.get(`s:${token}`, "json");
      if (!session) return edit("⏳ نشست منقضی شده.");
      await renderSettingsGroup(token, session, accounts, edit, "🔒 SSL / TLS", SSL_KEYS);
    } else if (data.startsWith("zsec:")) {
      const token = data.slice(5);
      const session = await kv.get(`s:${token}`, "json");
      if (!session) return edit("⏳ نشست منقضی شده.");
      await renderSettingsGroup(token, session, accounts, edit, "🛡 امنیت", SEC_KEYS);
    } else if (data.startsWith("zperf:")) {
      const token = data.slice(6);
      const session = await kv.get(`s:${token}`, "json");
      if (!session) return edit("⏳ نشست منقضی شده.");
      await renderSettingsGroup(token, session, accounts, edit, "⚡ کارایی", PERF_KEYS);
    } else if (data.startsWith("ztog:")) {
      const parts = data.split(":");
      const token = parts[1];
      const setting = parts[2];
      const session = await kv.get(`s:${token}`, "json");
      if (!session) return edit("⏳ نشست منقضی شده.");
      const zone = await getZoneById(session.zone_id, session.acc, accounts);
      const map = await getSettingsMap(zone, accounts);
      const cur = map[setting];
      const newVal = cur === "on" ? "off" : "on";
      const d = await setSetting(zone, accounts, setting, newVal);
      if (d.success) {
        await renderSettingsGroup(token, session, accounts, edit, groupTitleFor(setting), groupKeysFor(setting));
      } else {
        await edit("❌ خطا:\n" + cfErrText(d));
      }
    } else if (data.startsWith("zval:")) {
      const parts = data.split(":");
      const token = parts[1];
      const setting = parts[2];
      const session = await kv.get(`s:${token}`, "json");
      if (!session) return edit("⏳ نشست منقضی شده.");
      const zone = await getZoneById(session.zone_id, session.acc, accounts);
      const map = await getSettingsMap(zone, accounts);
      const info = SETTINGS_INFO[setting];
      const cur = map[setting];
      const buttons = Object.keys(info.values).map((v) => ({
        text: `${v === cur ? "✅ " : ""}${info.values[v]}`,
        callback_data: `zvset:${token}:${setting}:${v}`,
      }));
      const kb = grid2(buttons);
      kb.push([{ text: "⬅️ بازگشت", callback_data: `zset:${token}` }]);
      await edit(`🔧 ${info.label}:\n\nمقدار فعلی: ${info.values[cur] || cur}`, kb);
    } else if (data.startsWith("zvset:")) {
      const parts = data.split(":");
      const token = parts[1];
      const setting = parts[2];
      const value = parts[3];
      const session = await kv.get(`s:${token}`, "json");
      if (!session) return edit("⏳ نشست منقضی شده.");
      const zone = await getZoneById(session.zone_id, session.acc, accounts);
      const d = await setSetting(zone, accounts, setting, value);
      if (d.success) {
        await renderSettingsGroup(token, session, accounts, edit, groupTitleFor(setting), groupKeysFor(setting));
      } else {
        await edit("❌ خطا:\n" + cfErrText(d));
      }
    } else if (data.startsWith("zd:")) {
      const token = data.slice(3);
      const session = await kv.get(`s:${token}`, "json");
      if (!session) return edit("⏳ نشست منقضی شده.");
      const zone = await getZoneById(session.zone_id, session.acc, accounts);
      const text =
        `ℹ️ ${zone.name}\n\n` +
        `وضعیت: ${zone.status}\n` +
        `پلن: ${zone.plan ? zone.plan.name : "؟"}\n` +
        `NS ها:\n${(zone.name_servers || []).join("\n")}\n` +
        `ایجاد شده: ${new Date(zone.created_on).toLocaleDateString("fa-IR")}\n` +
        `SSL: ${zone.ssl ? zone.ssl.status : "؟"}`;
      await edit(text, [[{ text: "⬅️ بازگشت", callback_data: `zset:${token}` }]]);
    } else if (data.startsWith("zpurge:")) {
      const token = data.slice(7);
      const session = await kv.get(`s:${token}`, "json");
      if (!session) return edit("⏳ نشست منقضی شده.");
      const res = await fetch(`${CF_API}/zones/${session.zone_id}/purge_cache`, {
        method: "POST",
        headers: hdr(accounts[session.acc].token),
        body: JSON.stringify({ purge_everything: true }),
      });
      const d = await res.json();
      if (d.success) {
        await edit(`✅ کش ${session.zone_name} به طور کامل پاک شد.`, [
          [{ text: "⬅️ بازگشت", callback_data: `zset:${token}` }],
        ]);
      } else {
        await edit("❌ خطا:\n" + cfErrText(d));
      }
    } else if (data.startsWith("zdev:")) {
      const token = data.slice(5);
      const session = await kv.get(`s:${token}`, "json");
      if (!session) return edit("⏳ نشست منقضی شده.");
      const zone = await getZoneById(session.zone_id, session.acc, accounts);
      const newMode = zone.development_mode === 1 ? "off" : "on";
      const res = await fetch(`${CF_API}/zones/${session.zone_id}`, {
        method: "PATCH",
        headers: hdr(accounts[session.acc].token),
        body: JSON.stringify({ development_mode: newMode }),
      });
      const d = await res.json();
      if (d.success) {
        await edit(`✅ حالت توسعه ${newMode === "on" ? "روشن" : "خاموش"} شد.`, [
          [{ text: "⬅️ بازگشت", callback_data: `zset:${token}` }],
        ]);
      } else {
        await edit("❌ خطا:\n" + cfErrText(d));
      }
    } else if (data.startsWith("zpause:")) {
      const token = data.slice(7);
      const session = await kv.get(`s:${token}`, "json");
      if (!session) return edit("⏳ نشست منقضی شده.");
      const zone = await getZoneById(session.zone_id, session.acc, accounts);
      const newPaused = zone.status === "active";
      const res = await fetch(`${CF_API}/zones/${session.zone_id}`, {
        method: "PATCH",
        headers: hdr(accounts[session.acc].token),
        body: JSON.stringify({ paused: newPaused }),
      });
      const d = await res.json();
      if (d.success) {
        await edit(`✅ دامنه ${newPaused ? "متوقف" : "فعال"} شد.`, [
          [{ text: "⬅️ بازگشت", callback_data: `zset:${token}` }],
        ]);
      } else {
        await edit("❌ خطا:\n" + cfErrText(d));
      }
    } else if (data.startsWith("z:")) {
      const parts = data.split(":");
      const accIndex = Number(parts[1]);
      const zoneId = parts[2];
      const zone = await getZoneById(zoneId, accIndex, accounts);
      if (!zone) return edit("❌ دامنه پیدا نشد.");
      const records = await getRecords(zone, accounts, kv);
      const token = makeToken();
      const zctx = (await kv.get(`zctx:${chatId}`, "json")) || null;
      const zback = zctx && zctx.filter !== undefined ? `zf:${zctx.filter}:${Number(zctx.page) || 0}` : "zones";
      await kv.put(`s:${token}`, JSON.stringify({ zone_id: zone.id, zone_name: zone.name, acc: accIndex, page: 0, zback }), {
        expirationTtl: 86400,
      });
      if (records.length === 0) {
        const kb = [
          [{ text: "➕ افزودن", callback_data: `addz:${token}` }],
          [{ text: "⚙️ تنظیمات", callback_data: `zset:${token}` }],
          [{ text: "🔙 بازگشت", callback_data: zback }],
        ];
        await edit(`📭 رکوردی برای ${zone.name} یافت نشد.`, kb);
      } else {
        await renderRecords(zone, records, token, 0, edit, undefined, zback);
      }
    } else if (data.startsWith("p:")) {
      const parts = data.split(":");
      const token = parts[1];
      const page = Number(parts[2]);
      const session = await kv.get(`s:${token}`, "json");
      if (!session) return edit("⏳ نشست منقضی شده. دوباره /zones را بزنید.");
      session.page = page;
      await kv.put(`s:${token}`, JSON.stringify(session), { expirationTtl: 86400 });
      const zone = await getZoneById(session.zone_id, session.acc, accounts);
      const records = await getRecords(zone, accounts, kv);
      await renderRecords(zone, records, token, page, edit, undefined, session.zback);
    } else if (data.startsWith("rback:")) {
      const token = data.slice(6);
      const session = await kv.get(`s:${token}`, "json");
      if (!session) return edit("⏳ نشست منقضی شده.");
      const rpage = Number(session.page) || 0;
      if (session.provider === "arvan") {
        const records = await arvanGetAllRecords(arvanAccounts[session.acc].token, session.domain);
        return renderArvanRecords(session.domain, records, token, rpage, edit, "arvan");
      }
      const zone = await getZoneById(session.zone_id, session.acc, accounts);
      if (!zone) return edit("❌ دامنه پیدا نشد.");
      const records = await getRecords(zone, accounts, kv);
      await renderRecords(zone, records, token, rpage, edit, undefined, session.zback);
    } else if (data.startsWith("selmode:")) {
      const token = data.slice(8);
      const session = await kv.get(`s:${token}`, "json");
      if (!session) return edit("⏳ نشست منقضی شده.");
      const page = Number(session.page) || 0;
      await kv.put(`sel:${chatId}`, JSON.stringify({ token, ids: [], page }), { expirationTtl: 3600 });
      const zone = await getZoneById(session.zone_id, session.acc, accounts);
      const records = await getRecords(zone, accounts, kv);
      await renderRecords(zone, records, token, page, edit, [], session.zback);
    } else if (data.startsWith("sel:")) {
      const parts = data.split(":");
      const token = parts[1];
      const recordId = parts[2];
      const selState = (await kv.get(`sel:${chatId}`, "json")) || { token, ids: [], page: 0 };
      if (selState.token !== token) return edit("⏳ نشست منقضی شده.");
      const ids = selState.ids || [];
      const idx = ids.indexOf(recordId);
      if (idx >= 0) ids.splice(idx, 1);
      else ids.push(recordId);
      const page = Number(selState.page) || 0;
      await kv.put(`sel:${chatId}`, JSON.stringify({ token, ids, page }), { expirationTtl: 3600 });
      const session = await kv.get(`s:${token}`, "json");
      const zone = await getZoneById(session.zone_id, session.acc, accounts);
      const records = await getRecords(zone, accounts, kv);
      await renderRecords(zone, records, token, page, edit, ids, session.zback);
    } else if (data.startsWith("selp:")) {
      const parts = data.split(":");
      const token = parts[1];
      const page = Number(parts[2]);
      const selState = (await kv.get(`sel:${chatId}`, "json")) || { token, ids: [], page: 0 };
      selState.page = page;
      await kv.put(`sel:${chatId}`, JSON.stringify(selState), { expirationTtl: 3600 });
      const session = await kv.get(`s:${token}`, "json");
      const zone = await getZoneById(session.zone_id, session.acc, accounts);
      const records = await getRecords(zone, accounts, kv);
      await renderRecords(zone, records, token, page, edit, selState.ids || [], session.zback);
    } else if (data.startsWith("seldone:")) {
      const token = data.slice(8);
      const selState = await kv.get(`sel:${chatId}`, "json");
      const page = selState && Number(selState.page) ? Number(selState.page) : 0;
      await kv.delete(`sel:${chatId}`);
      const session = await kv.get(`s:${token}`, "json");
      const zone = await getZoneById(session.zone_id, session.acc, accounts);
      const records = await getRecords(zone, accounts, kv);
      await renderRecords(zone, records, token, page, edit, undefined, session.zback);
    } else if (data.startsWith("favsel:")) {
      const token = data.slice(7);
      const selState = await kv.get(`sel:${chatId}`, "json");
      if (!selState || !selState.ids || selState.ids.length === 0) return edit("⚠️ چیزی انتخاب نشده.");
      const session = await kv.get(`s:${token}`, "json");
      if (!session) return edit("⏳ نشست منقضی شده.");
      const favs = await getFavs(kv, chatId);
      let added = 0;
      for (const rid of selState.ids) {
        if (favExists(favs, session.zone_id, rid)) continue;
        const rec = await getRecordById(session.acc, session.zone_id, rid, accounts);
        if (!rec) continue;
        favs.push({ zone_id: session.zone_id, zone_name: session.zone_name, acc: session.acc, record_id: rid, name: rec.name, type: rec.type });
        added++;
      }
      await saveFavs(kv, chatId, favs);
      await kv.delete(`sel:${chatId}`);
      await edit(added > 0 ? `✅ ${added} ساب به منتخب‌ها اضافه شد.` : "ℹ️ این ساب‌ها از قبل در منتخب‌ها بودند.", []);
      await sleep(2000);
      await redrawRecordsList(kv, accounts, botToken, chatId, messageId, token, 0);
    } else if (data.startsWith("bulkdel:")) {
      const token = data.slice(8);
      const selState = await kv.get(`sel:${chatId}`, "json");
      if (!selState || !selState.ids || selState.ids.length === 0) return edit("⚠️ چیزی انتخاب نشده.");
      await edit(`⚠️ ${selState.ids.length} رکورد حذف شود؟`, [
        [{ text: "✅ بله، حذف کن", callback_data: `bulkdely:${token}` }, { text: "❌ انصراف", callback_data: `selmode:${token}` }],
      ]);
    } else if (data.startsWith("bulkdely:")) {
      const token = data.slice(9);
      const selState = await kv.get(`sel:${chatId}`, "json");
      if (!selState || !selState.ids) return edit("⏳ نشست منقضی شده.");
      const session = await kv.get(`s:${token}`, "json");
      let okCount = 0;
      for (const id of selState.ids) {
        const del = await fetch(`${CF_API}/zones/${session.zone_id}/dns_records/${id}`, {
          method: "DELETE",
          headers: hdr(accounts[session.acc].token),
        });
        const d = await del.json();
        if (d.success) okCount++;
      }
      await invalidateCache(kv, session.zone_id);
      await kv.delete(`sel:${chatId}`);
      await edit(`✅ تغییر یافت\n\n${okCount} از ${selState.ids.length} رکورد حذف شد.`, []);
      await sleep(2000);
      await redrawRecordsList(kv, accounts, botToken, chatId, messageId, token, 0);
    } else if (data.startsWith("bulkedit:")) {
      const token = data.slice(9);
      const selState = await kv.get(`sel:${chatId}`, "json");
      if (!selState || !selState.ids || selState.ids.length === 0) return edit("⚠️ چیزی انتخاب نشده.");
      const session = await kv.get(`s:${token}`, "json");
      await kv.put(
        `pend:${chatId}`,
        JSON.stringify({ type: "bulk_edit", zone_id: session.zone_id, acc: session.acc, ids: selState.ids, token, msgId: messageId }),
        { expirationTtl: 600 }
      );
      await edit("✏️ مقدار جدید را برای رکوردهای انتخاب‌شده بفرستید:", [
        [{ text: "⬅️ انصراف", callback_data: `selmode:${token}` }],
      ]);
    } else if (data.startsWith("bulktype:")) {
      const token = data.slice(9);
      const selState = await kv.get(`sel:${chatId}`, "json");
      if (!selState || !selState.ids || selState.ids.length === 0) return edit("⚠️ چیزی انتخاب نشده.");
      await edit("🔄 نوع جدید برای رکوردهای انتخاب‌شده:", [
        ...RECORD_TYPES.map((t) => [{ text: t, callback_data: `bulktypev:${token}:${t}` }]),
        [{ text: "⬅️ انصراف", callback_data: `selmode:${token}` }],
      ]);
    } else if (data.startsWith("bulktypev:")) {
      const parts = data.split(":");
      const token = parts[1];
      const newType = parts[2];
      const selState = await kv.get(`sel:${chatId}`, "json");
      if (!selState || !selState.ids || selState.ids.length === 0) return edit("⚠️ چیزی انتخاب نشده.");
      const session = await kv.get(`s:${token}`, "json");
      await kv.put(
        `pend:${chatId}`,
        JSON.stringify({ type: "bulk_type", zone_id: session.zone_id, acc: session.acc, ids: selState.ids, new_type: newType, token, msgId: messageId }),
        { expirationTtl: 600 }
      );
      await edit(`🔄 مقدار جدید برای نوع ${newType} را بفرستید:`, [
        [{ text: "⬅️ انصراف", callback_data: `selmode:${token}` }],
      ]);
    } else if (data.startsWith("se:")) {
      const parts = data.split(":");
      const token = parts[1];
      const idx = Number(parts[2]);
      const stored = await kv.get(`sr:${token}`, "json");
      if (!stored || !stored.results[idx]) return edit("⏳ نشست منقضی شده.");
      const res = stored.results[idx];
      const kb = [
        [{ text: "✏️ تغییر مقدار", callback_data: `sev:${token}:${idx}` }],
        [{ text: "🔄 تغییر نوع", callback_data: `set:${token}:${idx}` }],
        [{ text: "🔄 تغییر Proxy", callback_data: `sep:${token}:${idx}` }],
        [{ text: "⬅️ بازگشت", callback_data: `sr:${token}` }],
      ];
      await edit(`✏️ ${res.record.type}-${code(res.record.name)} (${code(res.zone_name)})`, kb);
    } else if (data.startsWith("sev:")) {
      const parts = data.split(":");
      const token = parts[1];
      const idx = Number(parts[2]);
      const stored = await kv.get(`sr:${token}`, "json");
      if (!stored || !stored.results[idx]) return edit("⏳ نشست منقضی شده.");
      const res = stored.results[idx];
      await kv.put(
        `pend:${chatId}`,
        JSON.stringify({ type: "edit_value", zone_id: res.zone_id, record_id: res.record.id, acc: res.acc, srToken: token, msgId: messageId, provider: res.provider || "cloudflare", domain: res.domain }),
        { expirationTtl: 600 }
      );
      await edit(`✏️ مقدار جدید برای ${res.record.name} را بفرستید:`, [
        [{ text: "⬅️ انصراف", callback_data: `sr:${token}` }],
      ]);
    } else if (data.startsWith("sep:")) {
      const parts = data.split(":");
      const token = parts[1];
      const idx = Number(parts[2]);
      const stored = await kv.get(`sr:${token}`, "json");
      if (!stored || !stored.results[idx]) return edit("⏳ نشست منقضی شده.");
      const res = stored.results[idx];
      const record = res.record;
      if (res.provider === "arvan") {
        const records = await arvanGetAllRecords(await arvanToken(kv, res.acc), res.domain);
        const orig = records.find((r) => r.id === record.id);
        if (!orig) return edit("❌ رکورد پیدا نشد.");
        orig.proxied = !record.proxied;
        const r2 = await arvanUpdateRecord(await arvanToken(kv, res.acc), res.domain, orig, orig.content);
        if (r2.success !== false) {
          const sum =
            `✅ تغییر یافت\n\n📛 ساب‌دامین: ${code(record.name)}\n\n` +
            `🔴 Proxy قبلی: ${!orig.proxied ? "روشن" : "خاموش"}\n` +
            `🟢 Proxy فعلی: ${orig.proxied ? "روشن" : "خاموش"}`;
          await edit(sum, []);
          await sleep(2000);
          await redrawSearchResultsNav(kv, accounts, botToken, chatId, messageId, token);
        } else {
          await edit("❌ خطا:\n" + cfErrText(r2));
        }
      } else {
        const r = await fetch(`${CF_API}/zones/${res.zone_id}/dns_records/${record.id}`, {
          method: "PATCH",
          headers: hdr(accounts[res.acc].token),
          body: JSON.stringify({ proxied: !record.proxied }),
        });
        const d = await r.json();
        if (d.success) {
          await invalidateCache(kv, res.zone_id);
          const sum =
            `✅ تغییر یافت\n\n📛 ساب‌دامین: ${code(record.name)}\n\n` +
            `🔴 Proxy قبلی: ${record.proxied ? "روشن" : "خاموش"}\n` +
            `🟢 Proxy فعلی: ${d.result.proxied ? "روشن" : "خاموش"}`;
          await edit(sum, []);
          await sleep(2000);
          await redrawSearchResultsNav(kv, accounts, botToken, chatId, messageId, token);
        } else {
          await edit("❌ خطا:\n" + cfErrText(d));
        }
      }
    } else if (data.startsWith("set:")) {
      const parts = data.split(":");
      const token = parts[1];
      const idx = Number(parts[2]);
      const stored = await kv.get(`sr:${token}`, "json");
      if (!stored || !stored.results[idx]) return edit("⏳ نشست منقضی شده.");
      const res = stored.results[idx];
      const kb = RECORD_TYPES.filter((t) => t !== res.record.type).map((t) => [
        { text: `به ${t}`, callback_data: `sett:${token}:${idx}:${t}` },
      ]);
      kb.push([{ text: "⬅️ بازگشت", callback_data: `sr:${token}` }]);
      await edit(`🔄 تبدیل نوع ${res.record.name} از ${res.record.type} به:`, kb);
    } else if (data.startsWith("sett:")) {
      const parts = data.split(":");
      const token = parts[1];
      const idx = Number(parts[2]);
      const newType = parts[3];
      const stored = await kv.get(`sr:${token}`, "json");
      if (!stored || !stored.results[idx]) return edit("⏳ نشست منقضی شده.");
      const res = stored.results[idx];
      await kv.put(
        `pend:${chatId}`,
        JSON.stringify({ type: "change_type", new_type: newType, zone_id: res.zone_id, record_id: res.record.id, acc: res.acc, srToken: token, msgId: messageId }),
        { expirationTtl: 600 }
      );
      await edit(`🔄 مقدار جدید برای نوع ${newType} (${res.record.name}) را بفرستید:`, [
        [{ text: "⬅️ انصراف", callback_data: `sr:${token}` }],
      ]);
    } else if (data.startsWith("sr:")) {
      const token = data.slice(3);
      const stored = await kv.get(`sr:${token}`, "json");
      if (!stored) return edit("⏳ نشست منقضی شده.");
      await renderSearchResults(token, stored.results, stored.query, stored.field, edit);
    } else if (data.startsWith("sd:")) {
      const parts = data.split(":");
      const token = parts[1];
      const idx = Number(parts[2]);
      const stored = await kv.get(`sr:${token}`, "json");
      if (!stored || !stored.results[idx]) return edit("⏳ نشست منقضی شده.");
      const res = stored.results[idx];
      await edit(`⚠️ مطمئنید حذف شود؟\n\n${res.record.type} — ${res.record.name} → ${res.record.content}`, [
        [{ text: "✅ بله", callback_data: `sdy:${token}:${idx}` }, { text: "❌ انصراف", callback_data: `sr:${token}` }],
      ]);
    } else if (data.startsWith("sdy:")) {
      const parts = data.split(":");
      const token = parts[1];
      const idx = Number(parts[2]);
      const stored = await kv.get(`sr:${token}`, "json");
      if (!stored || !stored.results[idx]) return edit("⏳ نشست منقضی شده.");
      const res = stored.results[idx];
      let delData;
      if (res.provider === "arvan") {
        const r = await arvanDeleteRecord(await arvanToken(kv, res.acc), res.domain, res.record.id);
        delData = r;
      } else {
        const del = await fetch(`${CF_API}/zones/${res.zone_id}/dns_records/${res.record.id}`, {
          method: "DELETE",
          headers: hdr(accounts[res.acc].token),
        });
        delData = await del.json();
      }
      if (delData.success || delData.success !== false) {
        if (res.provider !== "arvan") await invalidateCache(kv, res.zone_id);
        const gone = res.record;
        stored.results.splice(idx, 1);
        await kv.put(`sr:${token}`, JSON.stringify(stored), { expirationTtl: 3600 });
        const sum = `✅ حذف شد\n\n📛 ساب‌دامین: ${code(gone.name)}\n\n🔴 مقدار قبلی:\n${code(gone.content)}`;
        await edit(sum, []);
        await sleep(2000);
        await redrawSearchResultsNav(kv, accounts, botToken, chatId, messageId, token);
      } else {
        await edit("❌ خطا در حذف:\n" + cfErrText(delData));
      }
    } else if (data.startsWith("e:")) {
      const parts = data.split(":");
      const token = parts[1];
      const recordId = parts[2];
      const session = await kv.get(`s:${token}`, "json");
      const page = session && Number(session.page) ? Number(session.page) : 0;
      const backCb = session && session.provider === "arvan" ? `ap:${token}:${page}` : `p:${token}:${page}`;
      await kv.put(`dd:${chatId}:${messageId}`, JSON.stringify({ token, recordId, backCb }), { expirationTtl: 86400 });
      await renderRecordDetail(kv, accounts, edit, chatId, token, recordId);
    } else if (data.startsWith("ev:") || data.startsWith("et:")) {
      const parts = data.split(":");
      const token = parts[1];
      const recordId = parts[2];
      const field = data.startsWith("ev:") ? "edit_value" : "edit_ttl";
      const session = await kv.get(`s:${token}`, "json");
      if (!session) return edit("⏳ نشست منقضی شده.");
      await kv.put(
        `pend:${chatId}`,
        JSON.stringify({ type: field, zone_id: session.zone_id, record_id: recordId, acc: session.acc, token, msgId: messageId, provider: session.provider || "cloudflare", domain: session.domain, backCb: session.provider === "arvan" ? `ap:${token}:${Number(session.page) || 0}` : `p:${token}:${Number(session.page) || 0}` }),
        { expirationTtl: 600 }
      );
      await edit(
        field === "edit_ttl"
          ? "⏱ TTL جدید را بفرستید (عدد به ثانیه، یا 1 برای خودکار):"
          : "✏️ مقدار جدید را بفرستید (IP یا هدف CNAME):",
        [[{ text: "⬅️ انصراف", callback_data: `cancel:${token}` }]]
      );
    } else if (data.startsWith("cancel:")) {
      await kv.delete(`pend:${chatId}`);
      const token = data.slice(7);
      const session = await kv.get(`s:${token}`, "json");
      if (!session) return edit("⏳ نشست منقضی شده.", [[{ text: "🏠 منو", callback_data: "menu" }]]);
      const rp = Number(session.page) || 0;
      if (session.provider === "arvan") {
        try {
          const records = await arvanGetAllRecords(await arvanToken(kv, session.acc), session.domain);
          await renderArvanRecords(session.domain, records, token, rp, edit, "arvan");
        } catch (e) {
          await showArvanDomains(0, arvanAccounts, edit, kv);
        }
      } else {
        const zone = await getZoneById(session.zone_id, session.acc, accounts);
        const records = await getRecords(zone, accounts, kv);
        await renderRecords(zone, records, token, rp, edit, undefined, session.zback);
      }
    } else if (data.startsWith("ct:")) {
      const parts = data.split(":");
      const token = parts[1];
      const recordId = parts[2];
      const session = await kv.get(`s:${token}`, "json");
      if (!session) return edit("⏳ نشست منقضی شده.");
      const recRes = await fetch(`${CF_API}/zones/${session.zone_id}/dns_records/${recordId}`, {
        headers: hdr(accounts[session.acc].token),
      });
      const recData = await recRes.json();
      if (!recData.success) return edit("❌ رکورد پیدا نشد.");
      const record = recData.result;
      const kb = RECORD_TYPES.filter((t) => t !== record.type).map((t) => [
        { text: `به ${t}`, callback_data: `ctt:${token}:${recordId}:${t}` },
      ]);
      kb.push([{ text: "⬅️ بازگشت", callback_data: `e:${token}:${recordId}` }]);
      await edit(`🔄 تبدیل نوع ${record.name} از ${record.type} به:`, kb);
    } else if (data.startsWith("ctt:")) {
      const parts = data.split(":");
      const token = parts[1];
      const recordId = parts[2];
      const newType = parts[3];
      const session = await kv.get(`s:${token}`, "json");
      if (!session) return edit("⏳ نشست منقضی شده.");
      await kv.put(
        `pend:${chatId}`,
        JSON.stringify({ type: "change_type", new_type: newType, zone_id: session.zone_id, record_id: recordId, acc: session.acc, token, msgId: messageId }),
        { expirationTtl: 600 }
      );
      await edit(`🔄 مقدار جدید برای نوع ${newType} را بفرستید:`, [
        [{ text: "⬅️ انصراف", callback_data: `rback:${token}` }],
      ]);
    } else if (data.startsWith("ep:")) {
      const parts = data.split(":");
      const token = parts[1];
      const recordId = parts[2];
      const session = await kv.get(`s:${token}`, "json");
      if (!session) return edit("⏳ نشست منقضی شده.");
      let record;
      if (session.provider === "arvan") {
        const records = await arvanGetAllRecords(await arvanToken(kv, session.acc), session.domain);
        record = records.find((r) => r.id === recordId);
        if (!record) return edit("❌ رکورد پیدا نشد.");
      } else {
        const recRes = await fetch(`${CF_API}/zones/${session.zone_id}/dns_records/${recordId}`, {
          headers: hdr(accounts[session.acc].token),
        });
        const recData = await recRes.json();
        if (!recData.success) return edit("❌ رکورد پیدا نشد.");
        record = recData.result;
      }
      if (session.provider === "arvan") {
        const newProxied = !record.proxied;
        record.proxied = newProxied;
        const res = await arvanUpdateRecord(await arvanToken(kv, session.acc), session.domain, record, record.content);
        if (res.success !== false) {
          const sum =
            `✅ تغییر یافت\n\n📛 ساب‌دامین: ${code(record.name)}\n\n` +
            `🔴 Proxy قبلی: ${!newProxied ? "روشن" : "خاموش"}\n` +
            `🟢 Proxy فعلی: ${newProxied ? "روشن" : "خاموش"}`;
          await edit(sum, []);
          await sleep(2000);
          await redrawRecordDetailNav(kv, accounts, botToken, chatId, messageId);
        } else {
          await edit("❌ خطا:\n" + cfErrText(res));
        }
      } else {
        const res = await fetch(`${CF_API}/zones/${session.zone_id}/dns_records/${recordId}`, {
          method: "PATCH",
          headers: hdr(accounts[session.acc].token),
          body: JSON.stringify({ proxied: !record.proxied }),
        });
        const data = await res.json();
        if (data.success) {
          await invalidateCache(kv, session.zone_id);
          const sum =
            `✅ تغییر یافت\n\n📛 ساب‌دامین: ${code(record.name)}\n\n` +
            `🔴 Proxy قبلی: ${record.proxied ? "روشن" : "خاموش"}\n` +
            `🟢 Proxy فعلی: ${data.result.proxied ? "روشن" : "خاموش"}`;
          await edit(sum, []);
          await sleep(2000);
          await redrawRecordDetailNav(kv, accounts, botToken, chatId, messageId);
        } else {
          await edit("❌ خطا:\n" + cfErrText(data));
        }
      }
    } else if (data.startsWith("d:")) {
      const parts = data.split(":");
      const token = parts[1];
      const recordId = parts[2];
      const session = await kv.get(`s:${token}`, "json");
      if (!session) return edit("⏳ نشست منقضی شده.");
      let record;
      if (session.provider === "arvan") {
        const records = await arvanGetAllRecords(await arvanToken(kv, session.acc), session.domain);
        record = records.find((r) => r.id === recordId);
        if (!record) return edit("❌ رکورد پیدا نشد.");
      } else {
        const recRes = await fetch(`${CF_API}/zones/${session.zone_id}/dns_records/${recordId}`, {
          headers: hdr(accounts[session.acc].token),
        });
        const recData = await recRes.json();
        if (!recData.success) return edit("❌ رکورد پیدا نشد.");
        record = recData.result;
      }
      await edit(`⚠️ مطمئنید رکورد زیر حذف شود؟\n\n${record.type} — ${record.name} → ${record.content}`, [
        [{ text: "✅ بله، حذف کن", callback_data: `dy:${token}:${recordId}` }, { text: "❌ انصراف", callback_data: `rback:${token}` }],
      ]);
    } else if (data.startsWith("dy:")) {
      const parts = data.split(":");
      const token = parts[1];
      const recordId = parts[2];
      const session = await kv.get(`s:${token}`, "json");
      if (!session) return edit("⏳ نشست منقضی شده.");
      if (session.provider === "arvan") {
        const res = await arvanDeleteRecord(await arvanToken(kv, session.acc), session.domain, recordId);
        if (res.success !== false) {
          await redrawRecordsList(kv, accounts, botToken, chatId, messageId, token, 0);
        } else {
          await edit("❌ خطا در حذف:\n" + cfErrText(res));
        }
      } else {
        const del = await fetch(`${CF_API}/zones/${session.zone_id}/dns_records/${recordId}`, {
          method: "DELETE",
          headers: hdr(accounts[session.acc].token),
          signal: withTimeout(),
        });
        const delData = await del.json();
        if (delData.success) {
          await invalidateCache(kv, session.zone_id);
          await redrawRecordsList(kv, accounts, botToken, chatId, messageId, token, 0);
        } else {
          await edit("❌ خطا در حذف:\n" + cfErrText(delData));
        }
      }
    } else if (data === "pnl") {
      await renderNodeHome(edit, kv);
    } else if (data === "pnladd") {
      await edit("🧠 نام پنل پاسارگارد را بفرستید (مثلاً: پنل اصلی):", [[{ text: "🔙 انصراف", callback_data: "nd" }]]);
    } else if (data.startsWith("pnlx:")) {
      const i = Number(data.slice(5));
      const panels = await getPanels(kv);
      const p = panels[i];
      if (!p) return edit("❌ پنل پیدا نشد.", [[{ text: "🖥 مانیتور نود پاسارگارد", callback_data: "nd" }]]);
      await edit(`⚠️ پنل «${escHtml(p.name)}» حذف شود؟ (مانیتور نودِ متصل به آن هم حذف می‌شود)`, [
        [{ text: "✅ بله", callback_data: `pnlxx:${i}` }, { text: "❌ انصراف", callback_data: "nd" }],
      ]);
    } else if (data.startsWith("pnlxx:")) {
      const i = Number(data.slice(6));
      const panels = await getPanels(kv);
      const p = panels[i];
      if (!p) return edit("❌ پنل پیدا نشد.", [[{ text: "🖥 مانیتور نود پاسارگارد", callback_data: "nd" }]]);
      panels.splice(i, 1);
      await savePanels(kv, panels);
      const monitors = await getNodeMonitors(kv);
      const removed = monitors.filter((mo) => mo.panel_id === p.id);
      await saveNodeMonitors(kv, monitors.filter((mo) => mo.panel_id !== p.id));
      for (const mo of removed) await kv.delete(`ndst:${mo.id}`);
      await edit(`✅ پنل «${escHtml(p.name)}» حذف شد.`);
      await renderNodeHome(edit, kv);
    } else if (data === "mons") {
      await edit("🖥 مانیتورها\n\nیک بخش را انتخاب کنید:", [
        [
          { text: "🧭 مانیتور فیلتر شدن ساب", callback_data: "hf" },
          { text: "🖥 مانیتور نود پاسارگارد", callback_data: "nd" },
        ],
        [{ text: "🔐 مانیتور SSL", callback_data: "sslm" }, { text: "⏰ یادآور", callback_data: "rem" }],
        [{ text: "🏠 منو", callback_data: "menu" }],
      ]);
    } else if (data === "nd") {
      await renderNodeHome(edit, kv);
    } else if (data.startsWith("pnd:")) {
      const panels = await getPanels(kv);
      const monitors = await getNodeMonitors(kv);
      await renderPanelDetail(panels, monitors, Number(data.slice(4)), edit, kv);
    } else if (data === "ndhelp") {
      const base = await selfUrlBase(env, kv);
      const lines = [
        "ℹ️ راهنمای مانیتور نود",
        "",
        "این بخش وضعیت نودهای پنل‌های شما را نشان می‌دهد و وقتی نودی «قطع» یا دوباره «وصل» شد به همه ادمین‌ها پیام می‌دهد.",
        "",
        "• بدون کرون‌جاب و بدون درخواست مکرر به پنل: فقط وقتی خودِ سرور پنل رویدادی را به وب‌هوک بفرستد هشدار ارسال می‌شود (رویدادمحور/push).",
        "",
        "• لیست نودها: دکمه «🔄 همگام‌سازی با پنل» هر بار که بزنید نودهای فعلی پنل را می‌خواند (فقط به‌درخواست شما، نه به‌صورت خودکار).",
        "",
        "• وب‌هوک: از دکمه «🔗 وب‌هوک» آدرس و توکنِ مخصوص همین مانیتور را کپی کنید و روی سرور پنل، هر تغییر وضعیت نود را به آن آدرس POST کنید:",
        `  آدرس: ${base ? `${code(base + "/ndhook/<token>")}` : "… (WORKER_URL تنظیم نشده — از «🔗 وب‌هوک» ببینید)"}`,
        "  بدنه: { \"event\": \"down\" | \"up\", \"node\": \"نام نود\", \"reason\": \"علت قطع شدن\" }",
        "",
        "• «⏸ توقف هشدار» هشدارهای این پنل را نگه می‌دارد اما وضعیت نودها همچنان ثبت می‌شود.",
      ];
      await edit(lines.join("\n"), [[{ text: "🖥 مانیتور نود", callback_data: "nd" }]]);
    } else if (data === "nda") {
      const monitors = await getNodeMonitors(kv);
      const panels = await getPanels(kv);
      if (!panels.length) return edit("📭 ابتدا از «➕ افزودن پنل» در همین صفحه یک پنل پاسارگارد اضافه کنید.", [[{ text: "🖥 مانیتور نود پاسارگارد", callback_data: "nd" }]]);
      const avail = panels.filter((p) => !monitors.some((mo) => mo.panel_id === p.id));
      if (!avail.length) return edit("✅ برای همه پنل‌های ثبت‌شده، مانیتور نود ساخته شده.", [[{ text: "🖥 مانیتور نود", callback_data: "nd" }]]);
      const kb = avail.map((p) => [{ text: `🖥 ${p.name}`, callback_data: `nda:${p.id}` }]);
      kb.push([{ text: "🔙 بازگشت", callback_data: "nd" }]);
      await edit("برای کدام پنل، مانیتور نود بسازم؟", kb);
    } else if (data.startsWith("nda:")) {
      const panelId = data.slice(4);
      const panels = await getPanels(kv);
      const panel = panels.find((p) => p.id === panelId);
      if (!panel) return edit("❌ پنل پیدا نشد.", [[{ text: "🖥 مانیتور نود", callback_data: "nd" }]]);
      const monitors = await getNodeMonitors(kv);
      monitors.push({ id: makeToken() + makeToken(), panel_id: panel.id, name: panel.name, url: panel.url, token: makeToken() + makeToken(), enabled: true });
      await saveNodeMonitors(kv, monitors);
      const idx = monitors.length - 1;
      await edit("⏳ در حال ساخت مانیتور نود و همگام‌سازی اولیه…");
      const r = await nodeSyncFromPanel(monitors[idx], kv);
      if (r.error) return edit(`✅ مانیتور نود ساخته شد.\n❌ ${r.error}\nبعداً از «🔄 همگام‌سازی» دوباره امتحان کنید.`, [[{ text: "🔙 بازگشت", callback_data: `ndd:${idx}` }]]);
      await renderNodeMonitor(monitors, idx, edit, kv);
    } else if (data.startsWith("ndd:")) {
      const i = Number(data.slice(4));
      const monitors = await getNodeMonitors(kv);
      if (!monitors[i]) return edit("❌ مانیتور نود پیدا نشد.", [[{ text: "🖥 مانیتور نود", callback_data: "nd" }]]);
      await renderNodeMonitor(monitors, i, edit, kv);
    } else if (data.startsWith("ndsync:")) {
      const i = Number(data.slice(7));
      const monitors = await getNodeMonitors(kv);
      const m = monitors[i];
      if (!m) return edit("❌ مانیتور نود پیدا نشد.", [[{ text: "🖥 مانیتور نود", callback_data: "nd" }]]);
      await edit("⏳ در حال همگام‌سازی نودها با پنل…");
      const r = await nodeSyncFromPanel(m, kv);
      if (r.error) return edit(`❌ ${r.error}`, [[{ text: "🔙 بازگشت", callback_data: `ndd:${i}` }]]);
      await renderNodeMonitor(monitors, i, edit, kv);
    } else if (data.startsWith("ndtg:")) {
      const i = Number(data.slice(5));
      const monitors = await getNodeMonitors(kv);
      const m = monitors[i];
      if (!m) return edit("❌ مانیتور نود پیدا نشد.");
      m.enabled = m.enabled === false;
      await saveNodeMonitors(kv, monitors);
      await renderNodeMonitor(monitors, i, edit, kv);
    } else if (data.startsWith("nddel:")) {
      const i = Number(data.slice(6));
      const monitors = await getNodeMonitors(kv);
      const m = monitors[i];
      if (!m) return edit("❌ مانیتور نود پیدا نشد.");
      await edit(`⚠️ مانیتور نود «${escHtml(m.name)}» حذف شود؟ (هشدارهای بعدی برای این پنل ارسال نمی‌شود)`, [
        [{ text: "✅ بله", callback_data: `nddely:${i}` }, { text: "❌ انصراف", callback_data: `ndd:${i}` }],
      ]);
    } else if (data.startsWith("nddely:")) {
      const i = Number(data.slice(7));
      const monitors = await getNodeMonitors(kv);
      const m = monitors[i];
      if (!m) return edit("❌ مانیتور نود پیدا نشد.");
      const rm = monitors.splice(i, 1);
      await saveNodeMonitors(kv, monitors);
      if (rm[0]) await kv.delete(`ndst:${rm[0].id}`);
      await edit(`✅ مانیتور نود «${escHtml(m.name)}» حذف شد.`, [[{ text: "🖥 مانیتور نود", callback_data: "nd" }]]);
    } else if (data.startsWith("ndhook:")) {
      const i = Number(data.slice(7));
      const monitors = await getNodeMonitors(kv);
      const m = monitors[i];
      if (!m) return edit("❌ مانیتور نود پیدا نشد.");
      const base = await selfUrlBase(env, kv);
      const url = `${base || "https://<your-worker>.workers.dev"}/ndhook/${m.token}`;
      const lines = [
        `🔗 وب‌هوک مانیتور نود «${escHtml(m.name)}»`,
        "",
        "این آدرس را روی سرور پنل تنظیم کنید. هر بار که وضعیت یک نود تغییر کند، یک درخواست POST با بدنه JSON به این آدرس بفرستید:",
        "",
        `آدرس: ${code(url)}`,
        "",
        "نمونه بدنه برای قطع شدن:",
        `${code(JSON.stringify({ event: "down", node: "نام نود", reason: "علت قطع شدن" }))}`,
        "",
        "نمونه بدنه برای وصل شدن:",
        `${code(JSON.stringify({ event: "up", node: "نام نود", reason: "optional" }))}`,
        "",
        "اگر WORKER_URL تعریف نشده باشد، آدرس کامل بعد از اولین پیام به ربات به‌صورت خودکار تشخیص داده می‌شود.",
      ];
      await edit(lines.join("\n"), [[{ text: "🔙 بازگشت", callback_data: `ndd:${i}` }]]);
    } else if (data.startsWith("ndtest:")) {
      const i = Number(data.slice(7));
      const monitors = await getNodeMonitors(kv);
      const m = monitors[i];
      if (!m) return edit("❌ مانیتور نود پیدا نشد.");
      await send(
        "🧪 این فقط یک پیام آزمایشی است تا قالب هشدار قطع شدن را ببینید:\n\n" +
          "🚨 نود قطع شد!\n🖥 پنل: " +
          m.name +
          "\n🖧 نود: node-test\n⏱ زمان: " +
          ndFmtTs(new Date().toISOString()) +
          " به وقت ایران\n🔎 علت: اتصال به پنل از دست رفت (تست)"
      );
      await renderNodeMonitor(monitors, i, edit, kv);
    } else if (data.startsWith("ndi:") || data.startsWith("ndip:") || data.startsWith("ndx:")) {
      const parts = data.split(":");
      const mi = Number(parts[1]);
      const ni = Number(parts[2]);
      const monitors = await getNodeMonitors(kv);
      const m = monitors[mi];
      if (!m) return edit("❌ مانیتور نود پیدا نشد.", [[{ text: "🖥 مانیتور نود", callback_data: "nd" }]]);
      const st = await getNodeState(kv, m.id);
      const nm = sortedNodeNames(st)[ni];
      if (!nm) return edit("❌ نود پیدا نشد.", [[{ text: "🔙 بازگشت", callback_data: `ndd:${mi}` }]]);
      const nd = st.nodes[nm];
      if (data.startsWith("ndx:")) {
        const set = new Set(m.excluded || []);
        if (set.has(nm)) set.delete(nm);
        else set.add(nm);
        m.excluded = [...set];
        await saveNodeMonitors(kv, monitors);
        await renderNodeMonitor(monitors, mi, edit, kv);
      } else if (data.startsWith("ndip:")) {
        await edit(`🌐 آی‌پی نود «${escHtml(nm)}»:\n${code(nd.address || "—")}`, [[{ text: "🔙 بازگشت", callback_data: `ndd:${mi}` }]]);
      } else {
        const exc = (m.excluded || []).includes(nm);
        const lines = ["🖧 نود «" + escHtml(nm) + "»", nodeStatusEmoji(nd.status) + " " + nodeStatusLabel(nd.status)];
        if (nd.address) lines.push("🌐 " + code(nd.address));
        if (nd.version) lines.push("🧩 نسخه: " + code(nd.version));
        if (nd.first_seen) lines.push("🟢 اولین مشاهده: " + ndFmtTs(nd.first_seen));
        if (nd.ts) lines.push("🕐 آخرین وضعیت: " + ndFmtTs(nd.ts));
        if (nd.reason) lines.push("🔎 علت: " + escHtml(nd.reason));
        if (exc) lines.push("🚫 این نود استثنا شده.");
        await edit(lines.join("\n"), [
          [
            { text: "📡 آی‌پی", callback_data: `ndip:${mi}:${ni}` },
            { text: exc ? "✅ استثنا" : "🚫 استثنا", callback_data: `ndx:${mi}:${ni}` },
          ],
          [{ text: "⏰ ایجاد یادآور انقضا سرور", callback_data: `ndexp:${mi}:${ni}` }],
          [{ text: "🔙 بازگشت", callback_data: `ndd:${mi}` }],
        ]);
      }
    } else if (data.startsWith("ndexp:")) {
      const parts = data.split(":");
      const mi = Number(parts[1]);
      const ni = Number(parts[2]);
      const monitors = await getNodeMonitors(kv);
      const m = monitors[mi];
      if (!m) return edit("❌ مانیتور نود پیدا نشد.", [[{ text: "🖥 مانیتور نود", callback_data: "nd" }]]);
      const st = await getNodeState(kv, m.id);
      const nm = sortedNodeNames(st)[ni];
      if (!nm) return edit("❌ نود پیدا نشد.", [[{ text: "🔙 بازگشت", callback_data: `ndd:${mi}` }]]);
      const nd = st.nodes[nm];
      const target = { type: "server", label: `${nd.address || "—"} — ${nm}`, ip: nd.address || "", dc: nm, panel_id: m.panel_id };
      await kv.put(`pend:${chatId}`, JSON.stringify({ type: "rem_when", mode: "expiry", target, text: "" }), { expirationTtl: 1200 });
      await edit(
        "⏰ یادآور انقضای سرور\n\n" + (nd.address ? "🌐 " + code(nd.address) + "\n" : "") + "🖧 " + escHtml(nm) + "\n\nزمان انقضا را وارد کن:",
        remWhenKb()
      );
    } else if (data === "hf") {
      await renderHostFilterHome(edit, kv, env);
    } else if (data === "hflist") {
      await renderHostFilterHosts(edit, kv, env);
    } else if (data.startsWith("hfchk:")) {
      const parts = data.split(":");
      await edit("⏳ در حال بررسی این هاست…");
      const r = await hfHostCheck(kv, env, parts[1], parts[2]);
      await edit(r.text, r.kb);
    } else if (data.startsWith("hfexc:")) {
      const parts = data.split(":");
      const key = parts[1] + ":" + parts[2];
      const cfg = await getHostFilterCfg(kv);
      const set = new Set(cfg.exceptions || []);
      if (set.has(key)) set.delete(key);
      else set.add(key);
      cfg.exceptions = [...set];
      await saveHostFilterCfg(kv, cfg);
      await renderHostFilterHosts(edit, kv, env);
    } else if (data === "hftg") {
      const cfg = await getHostFilterCfg(kv);
      cfg.enabled = !cfg.enabled;
      await saveHostFilterCfg(kv, cfg);
      await renderHostFilterHome(edit, kv, env);
    } else if (data === "hfcheck") {
      const cfg = await getHostFilterCfg(kv);
      cfg.manual_request = { ts: new Date().toISOString(), by: chatId };
      await saveHostFilterCfg(kv, cfg);
      await edit("⏳ بررسی کامل همهٔ دامنه‌های هاست‌ها تا کمتر از یک دقیقه دیگر شروع می‌شود و نتیجه برایتان ارسال خواهد شد.", [[{ text: "🔙 بازگشت", callback_data: "hf" }]]);
    } else if (data === "hfhist") {
      const log = await kv.get("host_filter_log", "json");
      const lines = ["📜 تاریخچهٔ تعویض خودکار", ""];
      if (!Array.isArray(log) || !log.length) {
        lines.push("📭 هنوز رویدادی ثبت نشده.");
      } else {
        for (const e of log.slice(0, 15)) {
          const ts = ndFmtTs(e.ts);
          if (e.kind === "rotated") {
            lines.push(`🔄 ${ts} — هاست ${e.host_id}: ` + (e.events || []).map((ev) => `${ev.from}→${ev.to}`).join(", "));
          } else if (e.kind === "ip_blocked") {
            lines.push(`🚫 ${ts} — آی‌پی فیلتر: ${e.from} (${e.ip || "?"})`);
          } else if (e.kind === "revert") {
            lines.push(`↩️ ${ts} — بازگشت هاست ${e.host_id}`);
          } else if (e.kind === "protected") {
            lines.push(`🔒 ${ts} — فقط هشدار (${e.reason}): ${e.from}`);
          } else if (e.kind === "restore") {
            lines.push(`💾 ${ts} — بازگردانی بکاپ «${e.label || "-"}» (${e.ok} موفق / ${e.fail} ناموفق)`);
          } else if (e.kind === "external_sni") {
            lines.push(`⚠️ ${ts} — sni/host غیرقابل‌مدیریت: ${e.from}`);
          } else {
            lines.push(`⚠️ ${ts} — ${e.kind}${e.from ? " " + e.from : ""}${e.error ? " — " + e.error : ""}`);
          }
        }
      }
      await edit(lines.join("\n"), [[{ text: "🔙 بازگشت", callback_data: "hf" }]]);
    } else if (data === "hfset") {
      await renderHostFilterSettings(edit, kv);
    } else if (data === "hfsetprov") {
      const cfg = await getHostFilterCfg(kv);
      cfg.provider = cfg.provider === "checkhost" ? "globalping" : "checkhost";
      await saveHostFilterCfg(kv, cfg);
      await renderHostFilterSettings(edit, kv);
    } else if (data === "hfsettoken") {
      await kv.put(`pend:${chatId}`, JSON.stringify({ type: "hf_gptoken" }), { expirationTtl: 600 });
      await edit(
        "🔑 توکن Globalping را بفرستید (از dash.globalping.io).\nبرای حذف توکن، یک خط «-» بفرستید.",
        [[{ text: "🔙 انصراف", callback_data: "hfset" }]]
      );
    } else if (data === "hfcities") {
      await renderHostFilterCities(edit, kv);
    } else if (data.startsWith("hfcityt:")) {
      const c = data.slice(8);
      const cfg = await getHostFilterCfg(kv);
      if (!IR_CITIES.includes(c)) return renderHostFilterCities(edit, kv);
      const set = new Set(cfg.citiesSel);
      if (set.has(c)) {
        if (set.size > 1) set.delete(c);
      } else {
        set.add(c);
      }
      cfg.citiesSel = IR_CITIES.filter((x) => set.has(x));
      if (cfg.cities > cfg.citiesSel.length) cfg.cities = cfg.citiesSel.length;
      await saveHostFilterCfg(kv, cfg);
      await renderHostFilterCities(edit, kv);
    } else if (data.startsWith("hfsetedit:")) {
      const key = data.slice(10);
      await kv.put(`pend:${chatId}`, JSON.stringify({ type: "hf_set", key }), { expirationTtl: 600 });
      const hints = {
        interval: "⏱ فاصلهٔ اجرا را به دقیقه بفرستید (۱ تا ۱۴۴۰):",
        cities: "🎯 حداقل تعداد شهرهای فیلتر برای تعویض را بفرستید (۱ تا " + (await getHostFilterCfg(kv)).citiesSel.length + "):",
        maxok: "📶 حداکثر پینگ موفق مجاز هر پروب/نود را بفرستید (۰ تا ۳؛ ۰ یعنی فقط ۰ از ۴):",
        probes: "📡 حداکثر تعداد پروب‌های ایرانی Globalping را بفرستید (۱ تا ۵۰؛ ۵۰ = همه، پروب جدید خودکار اضافه می‌شود):",
        minfail: "🎯 حداقل تعداد پروب فیلتر برای تعویض را بفرستید (۱ تا ۵۰):",
        batch: "📦 تعداد دامنه‌های هر اجرا را بفرستید (۱ تا ۳۰):",
        maxchanges: "🔁 حداکثر تعویض در هر اجرا را بفرستید (۱ تا ۲۰):",
        backupkeep: "💾 تعداد بکاپ‌های نگه‌داشته را بفرستید (۱ تا ۱۰):",
      };
      await edit(hints[key] || "مقدار جدید را بفرستید:", [[{ text: "🔙 انصراف", callback_data: "hfset" }]]);
    } else if (data === "hfbk") {
      await renderHostFilterBackups(edit, kv);
    } else if (data === "hfbknow") {
      await edit("⏳ در حال گرفتن بکاپ از هاست‌ها…");
      const b = await hfSnapshot(kv, env, "دستی");
      await edit("✅ بکاپ «" + ndFmtTs(b.ts) + "» با " + b.count + " هاست ساخته شد.", [[{ text: "🔙 بکاپ‌ها", callback_data: "hfbk" }]]);
    } else if (data.startsWith("hfbkr:")) {
      const id = data.slice(6);
      await edit("⚠️ بازگردانی این بکاپ، مقادیر address/sni/host همهٔ هاست‌ها را به آن زمان برمی‌گرداند. مطمئنی؟", [
        [{ text: "✅ بله، بازگردان", callback_data: "hfbkrd:" + id }],
        [{ text: "❌ انصراف", callback_data: "hfbk" }],
      ]);
    } else if (data.startsWith("hfbkrd:")) {
      const id = data.slice(7);
      await edit("⏳ در حال بازگردانی بکاپ…");
      const r = await hfRestoreBackup(kv, env, id);
      if (r.error) {
        await edit("❌ بازگردانی ناموفق: " + escHtml(String(r.error)), [[{ text: "🔙 بکاپ‌ها", callback_data: "hfbk" }]]);
      } else {
        await edit("✅ بازگردانی انجام شد.\nموفق: " + r.ok + " — ناموفق: " + r.fail, [[{ text: "🔙 بکاپ‌ها", callback_data: "hfbk" }]]);
      }
    } else if (data.startsWith("hfbkdel:")) {
      const id = data.slice(8);
      const backups = (await getHfBackups(kv)).filter((b) => b.id !== id);
      await saveHfBackups(kv, backups);
      await renderHostFilterBackups(edit, kv);
    } else if (data.startsWith("hfrev:")) {
      const key = data.slice(6);
      const parts = key.split(":");
      await edit("⏳ در حال بازگردانی…");
      const r = await hostFilterRevert(kv, env, parts[0], parts[1]);
      if (r.error) {
        await edit("❌ بازگردانی ناموفق: " + escHtml(String(r.error)), [[{ text: "🔙 بازگشت", callback_data: "hf" }]]);
      } else {
        await edit("✅ به دامنهٔ قبلی برگشت.", [[{ text: "🧭 تعویض خودکار هاست فیلتر", callback_data: "hf" }]]);
      }
    } else if (data.startsWith("hokeep:")) {
      await edit("✅ تغییر حفظ شد.", [[{ text: "🧭 تعویض خودکار هاست فیلتر", callback_data: "hf" }]]);
    } else if (data === "sslm") {
      const monitors = await getSslMonitors(kv);
      let text = "🔐 مانیتور گواهی SSL\n\n";
      if (monitors.length === 0) {
        text += "📭 دامنه‌ای برای نظارت ثبت نشده.\nبرای هشدار هنگام نزدیک شدن به انقضا (پیش‌فرض ۵ روز)، یک دامنه اضافه کنید.";
      } else {
        const items = await sslCheckAll(kv);
        text += items.map((it) => sslResultLine(it)).join("\n");
      }
      const kb = [];
      kb.push([{ text: "➕ افزودن دامنه", callback_data: "sslma" }]);
      if (monitors.length > 0) {
        kb.push([{ text: "🔄 بررسی دوباره", callback_data: "sslm" }, { text: "🗑 حذف دامنه", callback_data: "sslmd" }]);
      }
      kb.push([{ text: "🏠 منو", callback_data: "menu" }]);
      await edit(text, kb);
    } else if (data === "sslma") {
      await kv.put(`pend:${chatId}`, JSON.stringify({ type: "ssl_host" }), { expirationTtl: 600 });
      await edit("🔐 دامنه یا ساب‌دامنه‌ای که می‌خواهید گواهی‌اش نظارت شود را بفرستید (مثلاً example.com):", [[{ text: "🔙 انصراف", callback_data: "sslm" }]]);
    } else if (data === "sslmd") {
      const monitors = await getSslMonitors(kv);
      if (monitors.length === 0) return edit("📭 دامنه‌ای ثبت نشده.", [[{ text: "🔙 بازگشت", callback_data: "sslm" }]]);
      const kb = monitors.map((m, i) => [{ text: `🗑 ${m.host}`, callback_data: `sslmdy:${i}` }]);
      kb.push([{ text: "🔙 بازگشت", callback_data: "sslm" }]);
      await edit("🗑 کدام دامنه از نظارت حذف شود؟", kb);
    } else if (data.startsWith("sslmdy:")) {
      const idx = Number(data.slice(7));
      const monitors = await getSslMonitors(kv);
      const removed = monitors[idx];
      if (!removed) return edit("❌ دامنه پیدا نشد.");
      monitors.splice(idx, 1);
      await saveSslMonitors(kv, monitors);
      await edit(`✅ «${removed.host}» از نظارت حذف شد.`, [[{ text: "🔐 مانیتور SSL", callback_data: "sslm" }]]);
    } else if (data === "providers") {
      await edit("🏢 دیتاسنترها\n\nیک ارائه‌دهنده را انتخاب کنید:", [
        [
          { text: "🇩🇪 هتزنر", callback_data: "hz" },
          { text: "🟢 لینود", callback_data: "ln" },
        ],
        [{ text: "🇮🇷 آروان", callback_data: "arvan" }],
        [{ text: "🏠 منو", callback_data: "menu" }],
      ]);
    } else if (data === "hz") {
      await showHzHome(hzAccounts, edit);
    } else if (data === "hza") {
      await kv.put(`pend:${chatId}`, JSON.stringify({ type: "hz_add_name" }), { expirationTtl: 600 });
      await edit("👤 نام دلخواه اکانت هتزنر را بفرستید (مثلاً: اصلی):", [[{ text: "🏠 منو", callback_data: "menu" }]]);
    } else if (data === "hzdel") {
      if (hzAccounts.length === 0) return edit("📭 اکانتی نیست.", [[{ text: "🔙 بازگشت", callback_data: "hz" }]]);
      const kb = hzAccounts.map((a, idx) => [{ text: `🗑 ${a.name}`, callback_data: `hzd:${idx}` }]);
      kb.push([{ text: "🔙 بازگشت", callback_data: "hz" }]);
      await edit("🗑 کدام اکانت حذف شود؟", kb);
    } else if (data.startsWith("hzd:")) {
      const idx = Number(data.slice(4));
      const acc = hzAccounts[idx];
      if (!acc) return edit("❌ اکانت پیدا نشد.", [[{ text: "🔙 بازگشت", callback_data: "hz" }]]);
      await edit(`⚠️ اکانت «${acc.name}» حذف شود؟`, [
        [{ text: "✅ بله", callback_data: `hzdy:${idx}` }, { text: "❌ انصراف", callback_data: "hz" }],
      ]);
    } else if (data.startsWith("hzdy:")) {
      const idx = Number(data.slice(5));
      hzAccounts.splice(idx, 1);
      await saveHzAccounts(kv, hzAccounts);
      await edit("✅ اکانت حذف شد.", [[{ text: "🇩🇪 هتزنر", callback_data: "hz" }, { text: "🏠 منو", callback_data: "menu" }]]);
    } else if (data.startsWith("hzm:")) {
      await showHzAccountMenu(hzAccounts, Number(data.slice(4)), edit);
    } else if (data.startsWith("hzacc:")) {
      const i = Number(data.slice(6));
      const acc = hzAccounts[i];
      if (!acc) return edit("❌ اکانت پیدا نشد.");
      await edit(`⚙️ اکانت «${acc.name}»\n\nتوکن: ${code(maskHzToken(acc.token))}`, [
        [{ text: "🗑 حذف اکانت", callback_data: `hzd:${i}` }],
        [{ text: "🔙 بازگشت", callback_data: `hzm:${i}` }],
      ]);
    } else if (data.startsWith("hzs:")) {
      const parts = data.split(":");
      await showHzServers(hzAccounts, Number(parts[1]), Number(parts[2]) || 0, edit);
    } else if (data.startsWith("hzsi:")) {
      const parts = data.split(":");
      await showHzServerInfo(hzAccounts, Number(parts[1]), parts[2], edit);
    } else if (data.startsWith("hzsc:")) {
      const i = Number(data.slice(5));
      await kv.put(`pend:${chatId}`, JSON.stringify({ type: "hz_srv_remark", acc: i }), { expirationTtl: 600 });
      await edit("➕ ساخت سرور\n\nنام سرور را بفرستید (بدون فاصله، مثلاً web1):", [[{ text: "🔙 انصراف", callback_data: `hzs:${i}:0` }]]);
    } else if (data.startsWith("hzscd:")) {
      const parts = data.split(":");
      const i = Number(parts[1]);
      const dcId = parts[2];
      const pend = await kv.get(`pend:${chatId}`, "json");
      if (!pend || pend.type !== "hz_srv_remark") return edit("⏳ عملیات منقضی شده.");
      const acc = hzAccounts[i];
      const types = await hzGetAll(acc.token, "/server_types");
      types.sort((a, b) => (parseFloat(a.prices && a.prices[0] && a.prices[0].price_monthly && a.prices[0].price_monthly.net) || 0) - (parseFloat(b.prices && b.prices[0] && b.prices[0].price_monthly && b.prices[0].price_monthly.net) || 0));
      await kv.put(`pend:${chatId}`, JSON.stringify({ ...pend, dcId }), { expirationTtl: 600 });
      const kb = grid2(types.map((t) => ({ text: t.name, callback_data: `hzscp:${i}:${t.id}` })));
      kb.push([{ text: "🔙 بازگشت", callback_data: `hzs:${i}:0` }]);
      await edit("💰 پلن سرور را انتخاب کنید:", kb);
    } else if (data.startsWith("hzscp:")) {
      const parts = data.split(":");
      const i = Number(parts[1]);
      const planId = parts[2];
      const pend = await kv.get(`pend:${chatId}`, "json");
      if (!pend || pend.type !== "hz_srv_remark") return edit("⏳ عملیات منقضی شده.");
      const acc = hzAccounts[i];
      const type = (await hzFetch(acc.token, `/server_types/${planId}`)).server_type;
      const imgs = await hzGetAll(acc.token, "/images");
      const avail = imgs.filter((im) => (im.type === "system" || im.type === "snapshot") && (!type || !type.architecture || im.architecture === type.architecture));
      if (!avail.length) return edit("❌ تصویری پیدا نشد.", [[{ text: "🔙 بازگشت", callback_data: `hzs:${i}:0` }]]);
      avail.sort((a, b) => (b.type === "system" ? 1 : 0) - (a.type === "system" ? 1 : 0));
      await kv.put(`pend:${chatId}`, JSON.stringify({ ...pend, planId }), { expirationTtl: 600 });
      const kb = grid2(avail.slice(0, 50).map((im) => ({ text: im.name || im.description || String(im.id), callback_data: `hzsci:${i}:${im.id}` })));
      kb.push([{ text: "🔙 بازگشت", callback_data: `hzs:${i}:0` }]);
      await edit("🖼️ تصویر (سیستم‌عامل) را انتخاب کنید:", kb);
    } else if (data.startsWith("hzsci:")) {
      const parts = data.split(":");
      const i = Number(parts[1]);
      const imageId = parts[2];
      const pend = await kv.get(`pend:${chatId}`, "json");
      if (!pend || pend.type !== "hz_srv_remark") return edit("⏳ عملیات منقضی شده.");
      const acc = hzAccounts[i];
      const r = await hzFetch(acc.token, "/servers", {
        method: "POST",
        body: JSON.stringify({ name: pend.remark, server_type: Number(pend.planId), image: Number(imageId), datacenter: Number(pend.dcId), start_after_create: true }),
      });
      if (r.error) return edit("❌ خطا: " + (r.error.message || ""));
      await kv.delete(`pend:${chatId}`);
      await edit("✅ سرور ساخته شد.", [[{ text: "🖥️ سرورها", callback_data: `hzs:${i}:0` }]]);
    } else if (data.startsWith("hzsu:")) {
      const parts = data.split(":");
      await hzServerDispatch(hzAccounts, Number(parts[1]), parts[2], parts[3], edit, kv, chatId);
    } else if (data.startsWith("hzsv:")) {
      const parts = data.split(":");
      await hzServerPick(hzAccounts, Number(parts[1]), parts[2], parts[3], parts[4], edit);
    } else if (data.startsWith("hzok:")) {
      const parts = data.split(":");
      await hzServerDo(hzAccounts, Number(parts[1]), parts[2], parts[3], parts[4], edit);
    } else if (data.startsWith("hzp:")) {
      const parts = data.split(":");
      await showHzPrimaryIps(hzAccounts, Number(parts[1]), Number(parts[2]) || 0, edit);
    } else if (data.startsWith("hzpi:")) {
      const parts = data.split(":");
      await showHzPrimaryIpInfo(hzAccounts, Number(parts[1]), parts[2], edit);
    } else if (data.startsWith("hzpc:")) {
      const parts = data.split(":");
      const i = Number(parts[1]);
      const type = parts[2];
      await kv.put(`pend:${chatId}`, JSON.stringify({ type: "hz_ip_remark", acc: i, ip_type: type }), { expirationTtl: 600 });
      await edit(`➕ ساخت آی‌پی ${type.toUpperCase()}\n\nنام (remark) آی‌پی را بفرستید:`, [[{ text: "🔙 انصراف", callback_data: `hzp:${i}:0` }]]);
    } else if (data.startsWith("hzpcd:")) {
      const parts = data.split(":");
      const i = Number(parts[1]);
      const dcId = parts[2];
      const pend = await kv.get(`pend:${chatId}`, "json");
      if (!pend || pend.type !== "hz_ip_remark") return edit("⏳ عملیات منقضی شده.");
      const acc = hzAccounts[i];
      const dc = (await hzFetch(acc.token, `/datacenters/${dcId}`)).datacenter;
      const locName = dc && dc.location && dc.location.name;
      if (!locName) return edit("❌ لوکیشن دیتاسنتر پیدا نشد.", [[{ text: "🔙 بازگشت", callback_data: `hzp:${i}:0` }]]);
      const body = { name: pend.remark, type: pend.ip_type, assignee_type: "server", location: locName };
      if (pend.ip_type === "ipv4") body.auto_delete = true;
      else body.auto_delete = false;
      const r = await hzFetch(acc.token, "/primary_ips", { method: "POST", body: JSON.stringify(body) });
      if (r.error) return edit("❌ خطا: " + (r.error.message || ""));
      await kv.delete(`pend:${chatId}`);
      await edit("✅ آی‌پی ساخته شد.", [[{ text: "🌐 آی‌پی‌ها", callback_data: `hzp:${i}:0` }]]);
    } else if (data.startsWith("hzpu:")) {
      const parts = data.split(":");
      await hzIpDispatch(hzAccounts, Number(parts[1]), parts[2], parts[3], edit, kv, chatId);
    } else if (data.startsWith("hzpv:")) {
      const parts = data.split(":");
      await hzIpPick(hzAccounts, Number(parts[1]), parts[2], parts[3], parts[4], edit);
    } else if (data.startsWith("hzpo:")) {
      const parts = data.split(":");
      await hzIpDo(hzAccounts, Number(parts[1]), parts[2], parts[3], edit);
    } else if (data.startsWith("hzn:")) {
      const parts = data.split(":");
      await showHzSnapshots(hzAccounts, Number(parts[1]), Number(parts[2]) || 0, edit);
    } else if (data.startsWith("hzni:")) {
      const parts = data.split(":");
      await showHzSnapshotInfo(hzAccounts, Number(parts[1]), parts[2], edit);
    } else if (data.startsWith("hznc:")) {
      const i = Number(data.slice(5));
      await kv.put(`pend:${chatId}`, JSON.stringify({ type: "hz_snap_remark", acc: i }), { expirationTtl: 600 });
      await edit("📸 ساخت اسنپ‌شات\n\nتوضیح (نام) اسنپ‌شات را بفرستید:", [[{ text: "🔙 انصراف", callback_data: `hzn:${i}:0` }]]);
    } else if (data.startsWith("hzns:")) {
      const parts = data.split(":");
      const i = Number(parts[1]);
      const serverId = parts[2];
      const pend = await kv.get(`pend:${chatId}`, "json");
      if (!pend || pend.type !== "hz_snap_remark") return edit("⏳ عملیات منقضی شده.");
      const acc = hzAccounts[i];
      const r = await hzFetch(acc.token, `/servers/${serverId}/actions/create_image`, {
        method: "POST",
        body: JSON.stringify({ description: pend.remark, type: "snapshot" }),
      });
      if (r.error) return edit("❌ خطا: " + (r.error.message || ""));
      await kv.delete(`pend:${chatId}`);
      await edit("✅ اسنپ‌شات ساخته شد.", [[{ text: "📸 اسنپ‌شات‌ها", callback_data: `hzn:${i}:0` }]]);
    } else if (data.startsWith("hznu:")) {
      const parts = data.split(":");
      await hzSnapshotDispatch(hzAccounts, Number(parts[1]), parts[2], parts[3], edit, kv, chatId);
    } else if (data.startsWith("hzno:")) {
      const parts = data.split(":");
      await hzSnapshotDo(hzAccounts, Number(parts[1]), parts[2], parts[3], edit);
    } else if (data === "rem") {
      await renderRemindersHome(kv, edit);
    } else if (data === "remnew") {
      await renderReminderTargets(edit);
    } else if (data === "remset") {
      const cfg = await getRemCfg(kv);
      const opts = [1, 3, 6, 12, 24, 48, 72];
      const rk = [];
      for (let i = 0; i < opts.length; i += 3) {
        rk.push(opts.slice(i, i + 3).map((h) => ({ text: (h === cfg.leadHours ? "✅ " : "") + h + " ساعت", callback_data: `remseth:${h}` })));
      }
      rk.push([{ text: "🔙 بازگشت", callback_data: "rem" }]);
      await edit(`⚙️ تنظیمات یادآور\n\nچند ساعت قبل از انقضا خبر بدم؟ (الان: ${cfg.leadHours} ساعت)`, rk);
    } else if (data.startsWith("remseth:")) {
      const h = Number(data.slice(8));
      if (!Number.isFinite(h) || h < 1 || h > 720) return edit("❌ مقدار نامعتبر.");
      await saveRemCfg(kv, { leadHours: h });
      await renderRemindersHome(kv, edit);
    } else if (data === "remsrv" || data === "remsrvf") {
      const force = data === "remsrvf";
      await edit(force ? "⏳ در حال بروزرسانی سرورها…" : "⏳ در حال خواندن سرورها…", [
        [{ text: "🏠 منو", callback_data: "menu" }],
      ]);
      let servers = null;
      try {
        servers = await getServersPicker(kv, force);
      } catch (e) {
        return edit("❌ خطا در خواندن سرورها: " + remPlain(e && e.message ? e.message : e), [[{ text: "🔙 بازگشت", callback_data: "remnew" }]]);
      }
      if (!servers || !servers.length) return edit("📭 سروری پیدا نشد.\n(ابتدا در «🖥 مانیتورهای پاسارگارد» پنل ثبت و نودها را همگام‌سازی کنید؛ سپس 🔄 بروزرسانی.)", [[{ text: "🔄 بروزرسانی", callback_data: "remsrvf" }, { text: "🔙 بازگشت", callback_data: "remnew" }]]);
      const token = makeToken();
      await kv.put(`rmsess:${token}`, JSON.stringify(servers), { expirationTtl: 1800 });
      await renderReminderServers(kv, token, 0, edit);
    } else if (data.startsWith("rempage:")) {
      const p = data.split(":");
      await renderReminderServers(kv, p[1], Number(p[2]) || 0, edit);
    } else if (data.startsWith("rempick:")) {
      const p = data.split(":");
      const servers = await kv.get(`rmsess:${p[1]}`, "json");
      const s = Array.isArray(servers) ? servers[Number(p[2])] : null;
      if (!s) return edit("⏳ نشست منقضی شده.", [[{ text: "🔙 بازگشت", callback_data: "remnew" }]]);
      const target = {
        type: "server",
        label: `${s.ip || "—"} — ${s.remark || s.panel_name || ""}`.trim(),
        ip: s.ip || "",
        dc: s.remark || "",
        panel: s.panel_name || "",
        host_id: s.host_id,
      };
      await kv.put(`pend:${chatId}`, JSON.stringify({ type: "rem_text", target }), { expirationTtl: 600 });
      await edit("✍️ متن یادآور را بفرستید:", [
        [{ text: "⏭ بدون متن", callback_data: "remnote" }],
        [{ text: "🔙 بازگشت", callback_data: "remnew" }],
      ]);
    } else if (data === "remtxt") {
      await kv.put(`pend:${chatId}`, JSON.stringify({ type: "rem_text", target: null }), { expirationTtl: 600 });
      await edit("✍️ متن یادآور را بفرستید:", [[{ text: "🔙 بازگشت", callback_data: "remnew" }]]);
    } else if (data === "remnote") {
      const pend = await kv.get(`pend:${chatId}`, "json");
      const target = pend && pend.type === "rem_text" ? pend.target : null;
      await kv.put(`pend:${chatId}`, JSON.stringify({ type: "rem_when", target, text: "" }), { expirationTtl: 900 });
      await edit(REM_WHEN_TEXT, remWhenKb());
    } else if (data === "remwhenback") {
      const pend = await kv.get(`pend:${chatId}`, "json");
      const target = pend && pend.target ? pend.target : null;
      const text = pend && pend.text ? pend.text : "";
      await kv.put(`pend:${chatId}`, JSON.stringify({ type: "rem_when", target, text, mode: pend && pend.mode ? pend.mode : "" }), { expirationTtl: 900 });
      await edit(REM_WHEN_TEXT, remWhenKb());
    } else if (data === "remrel") {
      const pend = await kv.get(`pend:${chatId}`, "json");
      if (!pend || (pend.type !== "rem_when" && pend.type !== "rem_rel" && pend.type !== "rem_abs")) return edit("⏳ عملیات منقضی شده.");
      await kv.put(`pend:${chatId}`, JSON.stringify({ type: "rem_rel", target: pend.target || null, text: pend.text || "", mode: pend.mode || "" }), { expirationTtl: 900 });
      await edit("⏳ بعد از چه زمانی؟", remRelKb());
    } else if (data.startsWith("remrelu:")) {
      const unit = data.slice(8);
      if (!REL_UNITS[unit]) return edit("❌ گزینه نامعتبر.");
      const pend = await kv.get(`pend:${chatId}`, "json");
      if (!pend || pend.type !== "rem_rel") return edit("⏳ عملیات منقضی شده.");
      await kv.put(`pend:${chatId}`, JSON.stringify({ type: "rem_rel_num", target: pend.target || null, text: pend.text || "", unit, mode: pend.mode || "" }), { expirationTtl: 900 });
      await edit(`⏳ بعد از چند ${REL_UNITS[unit]}؟ (فقط عدد بفرستید):`, [[{ text: "🔙 بازگشت", callback_data: "remrel" }]]);
    } else if (data === "remabs") {
      const pend = await kv.get(`pend:${chatId}`, "json");
      if (!pend || (pend.type !== "rem_when" && pend.type !== "rem_rel" && pend.type !== "rem_abs")) return edit("⏳ عملیات منقضی شده.");
      await kv.put(`pend:${chatId}`, JSON.stringify({ type: "rem_abs", target: pend.target || null, text: pend.text || "", mode: pend.mode || "" }), { expirationTtl: 900 });
      await edit("📅 سال را انتخاب کنید:", remYearKb());
    } else if (data.startsWith("remabsy:")) {
      const jy = Number(data.slice(8));
      const pend = await kv.get(`pend:${chatId}`, "json");
      if (!pend || (pend.type !== "rem_abs" && pend.type !== "rem_abs_m")) return edit("⏳ عملیات منقضی شده.");
      await kv.put(`pend:${chatId}`, JSON.stringify({ ...pend, type: "rem_abs_m", jy }), { expirationTtl: 900 });
      await edit(`📅 ماه را انتخاب کنید (${jy}):`, remMonthKb(jy));
    } else if (data.startsWith("remabsm:")) {
      const p = data.split(":");
      const jy = Number(p[1]);
      const jm = Number(p[2]);
      const pend = await kv.get(`pend:${chatId}`, "json");
      if (!pend || (pend.type !== "rem_abs_m" && pend.type !== "rem_abs")) return edit("⏳ عملیات منقضی شده.");
      await kv.put(`pend:${chatId}`, JSON.stringify({ ...pend, type: "rem_abs_day", jy, jm }), { expirationTtl: 900 });
      await edit(`📅 روز را وارد کنید (عدد) — ${jy}/${String(jm).padStart(2, "0")}:`, [[{ text: "🔙 بازگشت", callback_data: "remabs" }]]);
    } else if (data === "remabsman") {
      const pend = await kv.get(`pend:${chatId}`, "json");
      if (!pend || (pend.type !== "rem_abs" && pend.type !== "rem_abs_m")) return edit("⏳ عملیات منقضی شده.");
      await kv.put(`pend:${chatId}`, JSON.stringify({ type: "rem_when", target: pend.target || null, text: pend.text || "", mode: pend.mode || "" }), { expirationTtl: 900 });
      await edit("✍️ تاریخ و ساعت را بنویسید:\nمثال: 1405/06/20 14:30", [[{ text: "🔙 بازگشت", callback_data: "remabs" }]]);
    } else if (data === "remdel") {
      const list = (await getReminders(kv)).slice().sort((a, b) => a.at - b.at);
      if (!list.length) return edit("📭 یادآوری نیست.", [[{ text: "🔙 بازگشت", callback_data: "rem" }]]);
      const kb = list.slice(0, 20).map((r) => [
        { text: `🗑 ${fmtJalali(r.at)} ${r.text || (r.target && r.target.label) || ""}`.substring(0, 60), callback_data: `remdelx:${r.id}` },
      ]);
      kb.push([{ text: "🔙 بازگشت", callback_data: "rem" }]);
      await edit("🗑 کدام یادآور حذف شود؟", kb);
    } else if (data.startsWith("remdelx:")) {
      const id = data.slice(8);
      const list = await getReminders(kv);
      const item = list.find((r) => r.id === id);
      if (!item) return edit("❌ پیدا نشد.", [[{ text: "🔙 بازگشت", callback_data: "rem" }]]);
      await edit(`⚠️ این یادآور حذف شود؟\n🕒 ${fmtJalali(item.at)}\n📝 ${remPlain(item.text || "-")}`, [
        [{ text: "✅ بله", callback_data: `remdely:${id}` }, { text: "❌ انصراف", callback_data: "rem" }],
      ]);
    } else if (data.startsWith("remdely:")) {
      const id = data.slice(8);
      const list = await getReminders(kv);
      await saveReminders(kv, list.filter((r) => r.id !== id));
      await edit("✅ یادآور حذف شد.", [[{ text: "⏰ یادآورها", callback_data: "rem" }, { text: "🏠 منو", callback_data: "menu" }]]);
    } else if (data.startsWith("remack:")) {
      const id = data.slice(7);
      const list = await getReminders(kv);
      await saveReminders(kv, list.filter((r) => r.id !== id));
      await edit("👀 ثبت شد.", [[{ text: "⏰ یادآورها", callback_data: "rem" }, { text: "🏠 منو", callback_data: "menu" }]]);
    } else if (data.startsWith("remagain:")) {
      const id = data.slice(9);
      const list = await getReminders(kv);
      const r = list.find((x) => x.id === id);
      if (!r) return edit("⏳ یادآور پیدا نشد.", [[{ text: "⏰ یادآورها", callback_data: "rem" }]]);
      await edit("🔁 چند ساعت بعد دوباره یادآوری کنم؟", [
        [
          { text: "۱ ساعت", callback_data: `remagainx:${id}:1` },
          { text: "۶ ساعت", callback_data: `remagainx:${id}:6` },
          { text: "۲۴ ساعت", callback_data: `remagainx:${id}:24` },
        ],
        [{ text: "🔙 بازگشت", callback_data: "rem" }],
      ]);
    } else if (data.startsWith("remagainx:")) {
      const p = data.split(":");
      const id = p[1];
      const h = Number(p[2]);
      const list = await getReminders(kv);
      const r = list.find((x) => x.id === id);
      if (!r || !Number.isFinite(h)) return edit("⏳ یادآور پیدا نشد.", [[{ text: "⏰ یادآورها", callback_data: "rem" }]]);
      r.at = Date.now() + h * 3600 * 1000;
      r.notifiedAt = null;
      await saveReminders(kv, list);
      await edit(`✅ ${h} ساعت دیگر یادآوری می‌شود.`, [[{ text: "⏰ یادآورها", callback_data: "rem" }, { text: "🏠 منو", callback_data: "menu" }]]);
    } else if (data === "ln") {
      await showLnHome(lnAccounts, edit);
    } else if (data === "lna") {
      await kv.put(`pend:${chatId}`, JSON.stringify({ type: "ln_add_name" }), { expirationTtl: 600 });
      await edit("👤 نام دلخواه اکانت لینود را بفرستید (مثلاً: اصلی):", [[{ text: "🏠 منو", callback_data: "menu" }]]);
    } else if (data === "lndel") {
      if (lnAccounts.length === 0) return edit("📭 اکانتی نیست.", [[{ text: "🔙 بازگشت", callback_data: "ln" }]]);
      const kb = lnAccounts.map((a, idx) => [{ text: `🗑 ${a.name}`, callback_data: `lnd:${idx}` }]);
      kb.push([{ text: "🔙 بازگشت", callback_data: "ln" }]);
      await edit("🗑 کدام اکانت حذف شود؟", kb);
    } else if (data.startsWith("lnd:")) {
      const idx = Number(data.slice(4));
      const acc = lnAccounts[idx];
      if (!acc) return edit("❌ اکانت پیدا نشد.", [[{ text: "🔙 بازگشت", callback_data: "ln" }]]);
      await edit(`⚠️ اکانت «${acc.name}» حذف شود؟`, [
        [{ text: "✅ بله", callback_data: `lndy:${idx}` }, { text: "❌ انصراف", callback_data: "ln" }],
      ]);
    } else if (data.startsWith("lndy:")) {
      const idx = Number(data.slice(5));
      lnAccounts.splice(idx, 1);
      await saveLnAccounts(kv, lnAccounts);
      await edit("✅ اکانت حذف شد.", [[{ text: "🟢 لینود", callback_data: "ln" }, { text: "🏠 منو", callback_data: "menu" }]]);
    } else if (data.startsWith("lnm:")) {
      await showLnAccountMenu(lnAccounts, Number(data.slice(4)), edit);
    } else if (data.startsWith("lnacc:")) {
      const i = Number(data.slice(6));
      const acc = lnAccounts[i];
      if (!acc) return edit("❌ اکانت پیدا نشد.");
      await edit(`⚙️ اکانت «${acc.name}»\n\nتوکن: ${code(maskLnToken(acc.token))}`, [
        [{ text: "🗑 حذف اکانت", callback_data: `lnd:${i}` }],
        [{ text: "🔙 بازگشت", callback_data: `lnm:${i}` }],
      ]);
    } else if (data.startsWith("lns:")) {
      const parts = data.split(":");
      await showLnServers(lnAccounts, Number(parts[1]), Number(parts[2]) || 0, edit);
    } else if (data.startsWith("lnsi:")) {
      const parts = data.split(":");
      await showLnServerInfo(lnAccounts, Number(parts[1]), parts[2], edit);
    } else if (data.startsWith("lnsc:")) {
      const i = Number(data.slice(5));
      await kv.put(`pend:${chatId}`, JSON.stringify({ type: "ln_srv_remark", acc: i }), { expirationTtl: 600 });
      await edit("➕ ساخت سرور لینود\n\nنام سرور را بفرستید (بدون فاصله، مثلاً web1):", [[{ text: "🔙 انصراف", callback_data: `lns:${i}:0` }]]);
    } else if (data.startsWith("lnscd:")) {
      const parts = data.split(":");
      const i = Number(parts[1]);
      const region = parts[2];
      const pend = await kv.get(`pend:${chatId}`, "json");
      if (!pend || pend.type !== "ln_srv_remark") return edit("⏳ عملیات منقضی شده.");
      const acc = lnAccounts[i];
      const types = await lnGetAll(acc.token, "/linode/types");
      types.sort((a, b) => (lnRegionPrice(a, region).monthly || 0) - (lnRegionPrice(b, region).monthly || 0));
      await kv.put(`pend:${chatId}`, JSON.stringify({ ...pend, region }), { expirationTtl: 600 });
      const kb = grid2(
        types.map((t) => {
          const pr = lnRegionPrice(t, region);
          return { text: `${t.label} ($${pr.monthly || "?"}/m)`, callback_data: `lnscp:${i}:${region}:${t.id}` };
        })
      );
      kb.push([{ text: "🔙 بازگشت", callback_data: `lns:${i}:0` }]);
      await edit("💰 پلن سرور را انتخاب کنید:", kb);
    } else if (data.startsWith("lnscp:")) {
      const parts = data.split(":");
      const i = Number(parts[1]);
      const region = parts[2];
      const planId = parts[3];
      const pend = await kv.get(`pend:${chatId}`, "json");
      if (!pend || pend.type !== "ln_srv_remark") return edit("⏳ عملیات منقضی شده.");
      const acc = lnAccounts[i];
      const imgs = (await lnGetAll(acc.token, "/images")).filter((im) => im.is_public && im.status === "available");
      imgs.sort((a, b) => String(a.label).localeCompare(String(b.label)));
      if (!imgs.length) return edit("❌ تصویری پیدا نشد.", [[{ text: "🔙 بازگشت", callback_data: `lns:${i}:0` }]]);
      await kv.put(`pend:${chatId}`, JSON.stringify({ ...pend, region, planId }), { expirationTtl: 600 });
      const kb = grid2(imgs.slice(0, 60).map((im) => ({ text: im.label, callback_data: `lnsci:${i}:${im.id}` })));
      kb.push([{ text: "🔙 بازگشت", callback_data: `lns:${i}:0` }]);
      await edit("🖼️ تصویر (سیستم‌عامل) را انتخاب کنید:", kb);
    } else if (data.startsWith("lnsci:")) {
      const parts = data.split(":");
      const i = Number(parts[1]);
      const imageId = parts.slice(2).join(":");
      const pend = await kv.get(`pend:${chatId}`, "json");
      if (!pend || pend.type !== "ln_srv_remark") return edit("⏳ عملیات منقضی شده.");
      const acc = lnAccounts[i];
      const pass = lnRandomPass();
      const r = await lnFetch(acc.token, "/linode/instances", {
        method: "POST",
        body: JSON.stringify({ label: pend.remark, region: pend.region, type: pend.planId, image: imageId, root_pass: pass, booted: true }),
      });
      if (r.errors) return edit("❌ خطا: " + lnErr(r));
      await kv.delete(`pend:${chatId}`);
      await edit(`✅ سرور ساخته شد.\n🔑 رمز root: ${code(pass)}`, [[{ text: "🖥️ سرورها", callback_data: `lns:${i}:0` }]]);
    } else if (data.startsWith("lnsu:")) {
      const parts = data.split(":");
      await lnServerDispatch(lnAccounts, Number(parts[1]), parts[2], parts[3], edit, kv, chatId);
    } else if (data.startsWith("lnsv:")) {
      const parts = data.split(":");
      await lnServerPick(lnAccounts, Number(parts[1]), parts[2], parts[3], parts[4], edit);
    } else if (data.startsWith("lnok:")) {
      const parts = data.split(":");
      await lnServerDo(lnAccounts, Number(parts[1]), parts[2], parts[3], parts[4], edit);
    } else if (data.startsWith("lnp:")) {
      const parts = data.split(":");
      await showLnIps(lnAccounts, Number(parts[1]), Number(parts[2]) || 0, edit, kv);
    } else if (data.startsWith("lnpi:")) {
      const parts = data.split(":");
      await showLnIpInfo(lnAccounts, Number(parts[1]), parts[2], edit, kv);
    } else if (data.startsWith("lnpu:")) {
      const parts = data.split(":");
      await lnIpDispatch(lnAccounts, Number(parts[1]), parts[2], parts[3], edit, kv, chatId);
    } else if (data.startsWith("lnpv:")) {
      const parts = data.split(":");
      await lnIpPick(lnAccounts, Number(parts[1]), parts[2], parts[3], parts[4], edit, kv);
    } else if (data.startsWith("lnpo:")) {
      const parts = data.split(":");
      await lnIpDo(lnAccounts, Number(parts[1]), parts[2], parts[3], edit, kv);
    } else if (data.startsWith("lnn:")) {
      const parts = data.split(":");
      await showLnSnapshots(lnAccounts, Number(parts[1]), Number(parts[2]) || 0, edit);
    } else if (data.startsWith("lnni:")) {
      const parts = data.split(":");
      await showLnSnapshotInfo(lnAccounts, Number(parts[1]), parts[2], edit);
    } else if (data.startsWith("lnnc:")) {
      const i = Number(data.slice(5));
      await kv.put(`pend:${chatId}`, JSON.stringify({ type: "ln_snap_remark", acc: i }), { expirationTtl: 600 });
      await edit("📸 ساخت اسنپ‌شات\n\nیک نام برای اسنپ‌شات بفرستید:", [[{ text: "🔙 انصراف", callback_data: `lnn:${i}:0` }]]);
    } else if (data.startsWith("lnns:")) {
      const parts = data.split(":");
      const i = Number(parts[1]);
      const serverId = parts[2];
      const pend = await kv.get(`pend:${chatId}`, "json");
      if (!pend || pend.type !== "ln_snap_remark") return edit("⏳ عملیات منقضی شده.");
      const acc = lnAccounts[i];
      const disks = await lnGetAll(acc.token, `/linode/instances/${serverId}/disks`);
      const disk = disks.find((d) => d.filesystem && d.filesystem !== "swap") || disks[0];
      if (!disk) return edit("❌ دیسکی برای این سرور پیدا نشد.", [[{ text: "🔙 بازگشت", callback_data: `lnn:${i}:0` }]]);
      const r = await lnFetch(acc.token, "/images", { method: "POST", body: JSON.stringify({ disk_id: disk.id, label: pend.remark, description: pend.remark }) });
      if (r.errors) return edit("❌ خطا: " + lnErr(r));
      await kv.delete(`pend:${chatId}`);
      await edit("✅ اسنپ‌شات ساخته شد.", [[{ text: "📸 اسنپ‌شات‌ها", callback_data: `lnn:${i}:0` }]]);
    } else if (data.startsWith("lnnu:")) {
      const parts = data.split(":");
      await lnSnapshotDispatch(lnAccounts, Number(parts[1]), parts[2], parts[3], edit, kv, chatId);
    } else if (data.startsWith("lnno:")) {
      const parts = data.split(":");
      await lnSnapshotDo(lnAccounts, Number(parts[1]), parts[2], parts[3], edit);
    } else {
      const okFav = await dispatchFavQa(data, { kv, chatId, messageId, accounts, botToken, edit, send });
      if (!okFav) await edit("❓ عملیات ناشناخته.", mainMenuKeyboard());
    }
  } catch (err) {
    console.error("CALLBACK_ERROR", err && err.stack ? err.stack : String(err));
    await edit("❌ خطا:\n" + String(err && err.message ? err.message : err).substring(0, 3000));
  }
}

function typeKeyboard(token, backPage) {
  const kb = RECORD_TYPES.map((t) => [{ text: t, callback_data: `at:${token}:${t}` }]);
  kb.push([{ text: "⬅️ بازگشت", callback_data: `p:${token}:${backPage}` }]);
  return kb;
}

// ===================== Hetzner UI =====================
async function showHzHome(hzAccounts, edit) {
  const kb = [];
  for (let i = 0; i < hzAccounts.length; i += 2) {
    const row = [{ text: `👤 ${hzAccounts[i].name}`, callback_data: `hzm:${i}` }];
    row.push(i + 1 < hzAccounts.length ? { text: `👤 ${hzAccounts[i + 1].name}`, callback_data: `hzm:${i + 1}` } : EMPTY_BTN);
    kb.push(row);
  }
  kb.push([{ text: "➕ افزودن اکانت هتزنر", callback_data: "hza" }]);
  kb.push([{ text: "🗑 حذف اکانت", callback_data: "hzdel" }]);
  kb.push([{ text: "🏠 منو", callback_data: "menu" }]);
  await edit("🇩🇪 اکانت‌های هتزنر\n\nیک اکانت را انتخاب کنید:", kb);
}

async function showHzAccountMenu(hzAccounts, i, edit) {
  const acc = hzAccounts[i];
  if (!acc) return edit("❌ اکانت پیدا نشد.");
  await edit(
    `👤 ${acc.name}\n\nانتخاب کنید:`,
    [
      [{ text: "🖥️ سرورها", callback_data: `hzs:${i}:0` }],
      [{ text: "📸 اسنپ‌شات‌ها", callback_data: `hzn:${i}:0` }, { text: "🌐 آی‌پی‌های اصلی", callback_data: `hzp:${i}:0` }],
      [{ text: "⚙️ تنظیمات اکانت", callback_data: `hzacc:${i}` }],
      [{ text: "🔙 اکانت‌ها", callback_data: "hz" }, { text: "🏠 منو", callback_data: "menu" }],
    ]
  );
}

async function showHzServers(hzAccounts, i, page, edit) {
  const acc = hzAccounts[i];
  if (!acc) return edit("❌ اکانت پیدا نشد.");
  const servers = await hzGetAll(acc.token, "/servers");
  if (servers.length === 0) {
    return edit("📭 سروری یافت نشد.", [
      [{ text: "➕ ساخت سرور", callback_data: `hzsc:${i}` }],
      [{ text: "🔙 بازگشت", callback_data: `hzm:${i}` }],
    ]);
  }
  const pages = Math.ceil(servers.length / HZ_PAGE_SIZE);
  if (page < 0) page = 0;
  if (page >= pages) page = pages - 1;
  const slice = servers.slice(page * HZ_PAGE_SIZE, page * HZ_PAGE_SIZE + HZ_PAGE_SIZE);
  const kb = grid2(slice.map((s) => ({ text: hzServerListText(s), callback_data: `hzsi:${i}:${s.id}` })));
  const nav = [];
  nav.push(page > 0 ? { text: "◀️", callback_data: `hzs:${i}:${page - 1}` } : EMPTY_BTN);
  nav.push({ text: `📄 ${page + 1}/${pages}`, callback_data: "noop" });
  nav.push(page < pages - 1 ? { text: "▶️", callback_data: `hzs:${i}:${page + 1}` } : EMPTY_BTN);
  kb.push(nav);
  kb.push([{ text: "➕ ساخت سرور", callback_data: `hzsc:${i}` }]);
  kb.push([{ text: "🔙 بازگشت", callback_data: `hzm:${i}` }]);
  await edit(`🖥️ سرورهای «${acc.name}»:`, kb);
}

async function showHzServerInfo(hzAccounts, i, serverId, edit) {
  const acc = hzAccounts[i];
  if (!acc) return edit("❌ اکانت پیدا نشد.");
  const s = (await hzFetch(acc.token, `/servers/${serverId}`)).server;
  if (!s) return edit("❌ سرور پیدا نشد.");
  const in_gb = hzGb(s.ingoing_traffic);
  const out_gb = hzGb(s.outgoing_traffic);
  const total_gb = Math.round((in_gb + out_gb) * 1000) / 1000;
  const included_gb = hzGb(s.included_traffic);
  const used_pct = included_gb ? Math.round((out_gb / included_gb) * 10) / 10 : null;
  const billable = included_gb ? Math.round(Math.max(total_gb - included_gb, 0) * 1000) / 1000 : 0;
  let price = "—";
  const p = s.server_type && s.server_type.prices && s.server_type.prices[0];
  if (p) {
    price = `${p.price_monthly && p.price_monthly.gross ? p.price_monthly.gross : "—"}€/ماه · ${p.price_hourly && p.price_hourly.gross ? p.price_hourly.gross : "—"}€/ساعت`;
  }
  const text =
    `🚀 ${code(s.name)} [${code(s.status)}]\n\n` +
    `🔗 IPv4: ${code(s.public_net && s.public_net.ipv4 ? s.public_net.ipv4.ip : "—")}\n` +
    `🔗 IPv6: ${code(s.public_net && s.public_net.ipv6 ? s.public_net.ipv6.ip : "—")}\n` +
    `🌍 منطقه: ${code(s.datacenter ? `${s.datacenter.location.country}, ${s.datacenter.location.city}` : "—")}\n` +
    `⚙️ مشخصات: ${code(s.server_type ? `${s.server_type.cores} هسته / ${s.server_type.memory}GB رم / ${s.server_type.disk}GB دیسک` : "—")}\n` +
    `🖼️ تصویر: ${code(s.image ? (s.image.name || s.image.description) : "—")}\n` +
    `📊 ترافیک:\n • ورودی: ${code(in_gb + " GB")}\n • خروجی: ${code(out_gb + " GB")}\n • کل: ${code(total_gb + " GB")}\n • سهمیه: ${code(included_gb + " GB")}\n • مصرف: ${code(used_pct === null ? "—" : used_pct + "%")}\n • مازاد: ${code(billable + " GB")}\n` +
    `💰 قیمت: ${code(price)}`;
  const kb = grid2([
    { text: "⚡ روشن", callback_data: `hzsu:${i}:${serverId}:on` },
    { text: "🔌 خاموش", callback_data: `hzsu:${i}:${serverId}:off` },
    { text: "🔄 ریبوت", callback_data: `hzsu:${i}:${serverId}:reboot` },
    { text: "🔄 ریست", callback_data: `hzsu:${i}:${serverId}:reset` },
    { text: "🔓 ریست رمز", callback_data: `hzsu:${i}:${serverId}:pass` },
    { text: "✏️ تغییر نام", callback_data: `hzsu:${i}:${serverId}:rename` },
    { text: "🛠️ ریبیلد", callback_data: `hzsu:${i}:${serverId}:rebuild` },
    { text: "⬆️ ارتقا", callback_data: `hzsu:${i}:${serverId}:upgrade` },
    { text: "📷 اسنپ‌شات", callback_data: `hzsu:${i}:${serverId}:snap` },
    { text: "🗑 حذف اسنپ‌شات", callback_data: `hzsu:${i}:${serverId}:dsnap` },
    { text: "➕ IPv4", callback_data: `hzsu:${i}:${serverId}:a4` },
    { text: "➕ IPv6", callback_data: `hzsu:${i}:${serverId}:a6` },
    { text: "❌ IPv4", callback_data: `hzsu:${i}:${serverId}:u4` },
    { text: "❌ IPv6", callback_data: `hzsu:${i}:${serverId}:u6` },
    { text: "🗑 حذف سرور", callback_data: `hzsu:${i}:${serverId}:del` },
  ]);
  kb.push([{ text: "🔙 بازگشت", callback_data: `hzs:${i}:0` }]);
  await edit(text, kb);
}

async function hzServerDispatch(hzAccounts, i, serverId, step, edit, kv, chatId) {
  const acc = hzAccounts[i];
  if (!acc) return edit("❌ اکانت پیدا نشد.");
  const s = (await hzFetch(acc.token, `/servers/${serverId}`)).server;
  if (!s) return edit("❌ سرور پیدا نشد.");

  if (step === "rename") {
    await kv.put(`pend:${chatId}`, JSON.stringify({ type: "hz_srv_rename", acc: i, server_id: serverId }), { expirationTtl: 600 });
    return edit("✏️ نام جدید سرور را بفرستید:", [[{ text: "🔙 انصراف", callback_data: `hzsi:${i}:${serverId}` }]]);
  }
  if (step === "rebuild") {
    const imgs = await hzGetAll(acc.token, "/images");
    const avail = imgs.filter((x) => x.type === "system" || x.type === "snapshot");
    if (!avail.length) return edit("❌ تصویری پیدا نشد.", [[{ text: "🔙 بازگشت", callback_data: `hzsi:${i}:${serverId}` }]]);
    avail.sort((a, b) => (b.type === "system" ? 1 : 0) - (a.type === "system" ? 1 : 0));
    const kb = grid2(avail.slice(0, 50).map((im) => ({ text: im.name || im.description || String(im.id), callback_data: `hzsv:${i}:${serverId}:rebuild:${im.id}` })));
    kb.push([{ text: "🔙 بازگشت", callback_data: `hzsi:${i}:${serverId}` }]);
    return edit("🛠️ تصویر جدید برای ریبیلد:", kb);
  }
  if (step === "upgrade") {
    const types = await hzGetAll(acc.token, "/server_types");
    const cur = s.server_type;
    const up = types.filter(
      (t) => t.architecture === cur.architecture && t.id !== cur.id && (t.memory >= cur.memory || t.cores >= cur.cores || t.disk >= cur.disk)
    );
    if (!up.length) return edit("❌ پلن ارتقای بالاتری موجود نیست.", [[{ text: "🔙 بازگشت", callback_data: `hzsi:${i}:${serverId}` }]]);
    up.sort((a, b) => a.memory + a.cores + a.disk - (b.memory + b.cores + b.disk));
    const kb = grid2(up.map((t) => ({ text: `${t.name} (${t.cores}C/${t.memory}G/${t.disk}D)`, callback_data: `hzsv:${i}:${serverId}:upgrade:${t.id}` })));
    kb.push([{ text: "🔙 بازگشت", callback_data: `hzsi:${i}:${serverId}` }]);
    return edit("⬆️ پلن جدید را انتخاب کنید:", kb);
  }
  if (step === "a4" || step === "a6") {
    const type = step === "a4" ? "ipv4" : "ipv6";
    const ips = await hzGetAll(acc.token, "/primary_ips");
    const avail = ips.filter((ip) => !ip.assignee_id && ip.type === type);
    if (!avail.length) return edit(`❌ آی‌پی ${type} خالی پیدا نشد.`, [[{ text: "🔙 بازگشت", callback_data: `hzsi:${i}:${serverId}` }]]);
    const kb = grid2(avail.map((ip) => ({ text: ip.ip, callback_data: `hzsv:${i}:${serverId}:${step}:${ip.id}` })));
    kb.push([{ text: "🔙 بازگشت", callback_data: `hzsi:${i}:${serverId}` }]);
    return edit(`🔗 آی‌پی ${type.toUpperCase()} برای اختصاص:`, kb);
  }
  if (step === "dsnap") {
    const imgs = await hzGetAll(acc.token, "/images");
    const snaps = imgs.filter((im) => im.type === "snapshot" && im.created_from && im.created_from.id === Number(serverId));
    if (!snaps.length) return edit("❌ اسنپ‌شاتی برای این سرور پیدا نشد.", [[{ text: "🔙 بازگشت", callback_data: `hzsi:${i}:${serverId}` }]]);
    const kb = grid2(snaps.map((im) => ({ text: im.name || im.description || String(im.id), callback_data: `hzsv:${i}:${serverId}:dsnap:${im.id}` })));
    kb.push([{ text: "🔙 بازگشت", callback_data: `hzsi:${i}:${serverId}` }]);
    return edit("🗑 اسنپ‌شات برای حذف:", kb);
  }
  const label = { on: "روشن کردن", off: "خاموش کردن", reset: "ریست", reboot: "ریبوت", pass: "ریست رمز", del: "حذف سرور", snap: "ساخت اسنپ‌شات", u4: "حذف IPv4", u6: "حذف IPv6" }[step];
  return edit(`⚠️ مطمئنید «${label}» روی «${s.name}» انجام شود؟`, [
    [{ text: "✅ بله", callback_data: `hzok:${i}:${serverId}:${step}` }, { text: "❌ انصراف", callback_data: `hzsi:${i}:${serverId}` }],
  ]);
}

async function hzServerPick(hzAccounts, i, serverId, step, arg, edit) {
  const acc = hzAccounts[i];
  const s = (await hzFetch(acc.token, `/servers/${serverId}`)).server;
  if (!s) return edit("❌ سرور پیدا نشد.");
  const label = { rebuild: "ریبیلد", upgrade: "ارتقا", a4: "اختصاص IPv4", a6: "اختصاص IPv6", dsnap: "حذف اسنپ‌شات" }[step];
  return edit(`⚠️ مطمئنید «${label}» روی «${s.name}» انجام شود؟`, [
    [{ text: "✅ بله", callback_data: `hzok:${i}:${serverId}:${step}:${arg}` }, { text: "❌ انصراف", callback_data: `hzsi:${i}:${serverId}` }],
  ]);
}

async function hzServerDo(hzAccounts, i, serverId, step, arg, edit) {
  const acc = hzAccounts[i];
  const token = acc.token;
  const back = [[{ text: "🔙 بازگشت", callback_data: `hzsi:${i}:${serverId}` }]];
  const backList = [[{ text: "🖥️ سرورها", callback_data: `hzs:${i}:0` }]];
  if (step === "del") {
    const r = await hzFetch(token, `/servers/${serverId}`, { method: "DELETE" });
    if (r.error) return edit("❌ خطا: " + (r.error.message || ""));
    return edit("✅ سرور حذف شد.", backList);
  }
  if (step === "a4" || step === "a6") {
    const r = await hzFetch(token, `/primary_ips/${arg}/actions/assign`, {
      method: "POST",
      body: JSON.stringify({ assignee_id: Number(serverId), assignee_type: "server" }),
    });
    if (r.error) return edit("❌ خطا: " + (r.error.message || ""));
    return edit("✅ آی‌پی اختصاص یافت.", back);
  }
  if (step === "u4" || step === "u6") {
    const s = (await hzFetch(token, `/servers/${serverId}`)).server;
    const ipId = s.public_net && s.public_net[step === "u4" ? "primary_ipv4" : "primary_ipv6"];
    if (!ipId) return edit("❌ آی‌پی اختصاصی وجود ندارد.", back);
    const r = await hzFetch(token, `/primary_ips/${ipId}/actions/unassign`, { method: "POST", body: "{}" });
    if (r.error) return edit("❌ خطا: " + (r.error.message || ""));
    return edit("✅ آی‌پی حذف شد.", back);
  }
  if (step === "dsnap") {
    const r = await hzFetch(token, `/images/${arg}`, { method: "DELETE" });
    if (r.error) return edit("❌ خطا: " + (r.error.message || ""));
    return edit("✅ اسنپ‌شات حذف شد.", back);
  }
  let path = "";
  let body = {};
  switch (step) {
    case "on": path = `/servers/${serverId}/actions/poweron`; break;
    case "off": path = `/servers/${serverId}/actions/poweroff`; break;
    case "reset": path = `/servers/${serverId}/actions/reset`; break;
    case "reboot": path = `/servers/${serverId}/actions/reboot`; break;
    case "pass": path = `/servers/${serverId}/actions/reset_password`; break;
    case "snap": path = `/servers/${serverId}/actions/create_image`; body = { type: "snapshot" }; break;
    case "rebuild": path = `/servers/${serverId}/actions/rebuild`; body = { image: Number(arg) }; break;
    case "upgrade": path = `/servers/${serverId}/actions/change_type`; body = { server_type: Number(arg), upgrade_disk: true }; break;
    default: return edit("❓ عملیات ناشناخته.");
  }
  const r = await hzFetch(token, path, { method: "POST", body: JSON.stringify(body) });
  if (r.error) return edit("❌ خطا: " + (r.error.message || ""));
  if (step === "pass" && r.root_password) {
    return edit(`✅ رمز جدید سرور: ${code(r.root_password)}`, back);
  }
  return edit("✅ انجام شد.", back);
}

async function showHzPrimaryIps(hzAccounts, i, page, edit) {
  const acc = hzAccounts[i];
  if (!acc) return edit("❌ اکانت پیدا نشد.");
  const ips = await hzGetAll(acc.token, "/primary_ips");
  if (ips.length === 0) {
    return edit("📭 آی‌پی اصلی‌ای یافت نشد.", [
      [{ text: "➕ ساخت IPv4", callback_data: `hzpc:${i}:ipv4` }, { text: "➕ ساخت IPv6", callback_data: `hzpc:${i}:ipv6` }],
      [{ text: "🔙 بازگشت", callback_data: `hzm:${i}` }],
    ]);
  }
  const pages = Math.ceil(ips.length / HZ_PAGE_SIZE);
  if (page < 0) page = 0;
  if (page >= pages) page = pages - 1;
  const slice = ips.slice(page * HZ_PAGE_SIZE, page * HZ_PAGE_SIZE + HZ_PAGE_SIZE);
  const kb = grid2(slice.map((ip) => ({ text: `${ip.type === "ipv4" ? "4️⃣" : "6️⃣"} ${ip.ip}${ip.assignee_id ? " (متصل)" : ""}`, callback_data: `hzpi:${i}:${ip.id}` })));
  const nav = [];
  nav.push(page > 0 ? { text: "◀️", callback_data: `hzp:${i}:${page - 1}` } : EMPTY_BTN);
  nav.push({ text: `📄 ${page + 1}/${pages}`, callback_data: "noop" });
  nav.push(page < pages - 1 ? { text: "▶️", callback_data: `hzp:${i}:${page + 1}` } : EMPTY_BTN);
  kb.push(nav);
  kb.push([{ text: "➕ ساخت IPv4", callback_data: `hzpc:${i}:ipv4` }, { text: "➕ ساخت IPv6", callback_data: `hzpc:${i}:ipv6` }]);
  kb.push([{ text: "🔙 بازگشت", callback_data: `hzm:${i}` }]);
  await edit(`🌐 آی‌پی‌های اصلی «${acc.name}»:`, kb);
}

async function showHzPrimaryIpInfo(hzAccounts, i, ipId, edit) {
  const acc = hzAccounts[i];
  if (!acc) return edit("❌ اکانت پیدا نشد.");
  const ip = (await hzFetch(acc.token, `/primary_ips/${ipId}`)).primary_ip;
  if (!ip) return edit("❌ آی‌پی پیدا نشد.");
  let assignee = "—";
  if (ip.assignee_id) {
    const s = (await hzFetch(acc.token, `/servers/${ip.assignee_id}`)).server;
    if (s) assignee = s.name;
  }
  const text =
    `🌐 آی‌پی اصلی\n\n` +
    `🏷 نام: ${code(ip.name || "—")}\n` +
    `🔗 IP: ${code(ip.ip)}\n` +
    `🔤 نوع: ${code(ip.type)}\n` +
    `🔗 متصل به: ${code(assignee)}\n` +
    `📅 ساخته‌شده: ${code(ip.created ? ip.created.slice(0, 10) : "—")}`;
  const kb = grid2([
    { text: "✏️ تغییر نام", callback_data: `hzpu:${i}:${ipId}:rename` },
    { text: "🔗 اختصاص به سرور", callback_data: `hzpu:${i}:${ipId}:assign` },
    { text: "❌ حذف اختصاص", callback_data: `hzpu:${i}:${ipId}:unassign` },
    { text: "🗑 حذف آی‌پی", callback_data: `hzpu:${i}:${ipId}:del` },
  ]);
  kb.push([{ text: "🔙 بازگشت", callback_data: `hzp:${i}:0` }]);
  await edit(text, kb);
}

async function hzIpDispatch(hzAccounts, i, ipId, step, edit, kv, chatId) {
  const acc = hzAccounts[i];
  const ip = (await hzFetch(acc.token, `/primary_ips/${ipId}`)).primary_ip;
  if (!ip) return edit("❌ آی‌پی پیدا نشد.");
  if (step === "rename") {
    await kv.put(`pend:${chatId}`, JSON.stringify({ type: "hz_ip_rename", acc: i, ip_id: ipId }), { expirationTtl: 600 });
    return edit("✏️ نام جدید آی‌پی را بفرستید:", [[{ text: "🔙 انصراف", callback_data: `hzpi:${i}:${ipId}` }]]);
  }
  if (step === "assign") {
    const servers = await hzGetAll(acc.token, "/servers");
    if (!servers.length) return edit("❌ سروری پیدا نشد.", [[{ text: "🔙 بازگشت", callback_data: `hzpi:${i}:${ipId}` }]]);
    const kb = grid2(servers.map((s) => ({ text: s.name, callback_data: `hzpv:${i}:${ipId}:assign:${s.id}` })));
    kb.push([{ text: "🔙 بازگشت", callback_data: `hzpi:${i}:${ipId}` }]);
    return edit("🔗 سرور مقصد را انتخاب کنید:", kb);
  }
  const label = step === "unassign" ? "حذف اختصاص آی‌پی" : "حذف آی‌پی";
  return edit(`⚠️ مطمئنید «${label}» انجام شود؟`, [
    [{ text: "✅ بله", callback_data: `hzpo:${i}:${ipId}:${step}` }, { text: "❌ انصراف", callback_data: `hzpi:${i}:${ipId}` }],
  ]);
}

async function hzIpPick(hzAccounts, i, ipId, step, arg, edit) {
  const acc = hzAccounts[i];
  const r = await hzFetch(acc.token, `/primary_ips/${ipId}/actions/assign`, {
    method: "POST",
    body: JSON.stringify({ assignee_id: Number(arg), assignee_type: "server" }),
  });
  if (r.error) return edit("❌ خطا: " + (r.error.message || ""));
  return edit("✅ آی‌پی اختصاص یافت.", [[{ text: "🔙 بازگشت", callback_data: `hzpi:${i}:${ipId}` }]]);
}

async function hzIpDo(hzAccounts, i, ipId, step, edit) {
  const acc = hzAccounts[i];
  if (step === "del") {
    const r = await hzFetch(acc.token, `/primary_ips/${ipId}`, { method: "DELETE" });
    if (r.error) return edit("❌ خطا: " + (r.error.message || ""));
    return edit("✅ آی‌پی حذف شد.", [[{ text: "🌐 آی‌پی‌ها", callback_data: `hzp:${i}:0` }]]);
  }
  if (step === "unassign") {
    const r = await hzFetch(acc.token, `/primary_ips/${ipId}/actions/unassign`, { method: "POST", body: "{}" });
    if (r.error) return edit("❌ خطا: " + (r.error.message || ""));
    return edit("✅ اختصاص حذف شد.", [[{ text: "🔙 بازگشت", callback_data: `hzpi:${i}:${ipId}` }]]);
  }
  return edit("❓ عملیات ناشناخته.");
}

async function showHzSnapshots(hzAccounts, i, page, edit) {
  const acc = hzAccounts[i];
  if (!acc) return edit("❌ اکانت پیدا نشد.");
  const snaps = (await hzGetAll(acc.token, "/images")).filter((x) => x.type === "snapshot");
  if (snaps.length === 0) {
    return edit("📭 اسنپ‌شاتی یافت نشد.", [
      [{ text: "➕ ساخت اسنپ‌شات", callback_data: `hznc:${i}` }],
      [{ text: "🔙 بازگشت", callback_data: `hzm:${i}` }],
    ]);
  }
  const pages = Math.ceil(snaps.length / HZ_PAGE_SIZE);
  if (page < 0) page = 0;
  if (page >= pages) page = pages - 1;
  const slice = snaps.slice(page * HZ_PAGE_SIZE, page * HZ_PAGE_SIZE + HZ_PAGE_SIZE);
  const kb = grid2(slice.map((im) => ({ text: im.name || im.description || String(im.id), callback_data: `hzni:${i}:${im.id}` })));
  const nav = [];
  nav.push(page > 0 ? { text: "◀️", callback_data: `hzn:${i}:${page - 1}` } : EMPTY_BTN);
  nav.push({ text: `📄 ${page + 1}/${pages}`, callback_data: "noop" });
  nav.push(page < pages - 1 ? { text: "▶️", callback_data: `hzn:${i}:${page + 1}` } : EMPTY_BTN);
  kb.push(nav);
  kb.push([{ text: "➕ ساخت اسنپ‌شات", callback_data: `hznc:${i}` }]);
  kb.push([{ text: "🔙 بازگشت", callback_data: `hzm:${i}` }]);
  await edit(`📸 اسنپ‌شات‌های «${acc.name}»:`, kb);
}

async function showHzSnapshotInfo(hzAccounts, i, imageId, edit) {
  const acc = hzAccounts[i];
  const im = (await hzFetch(acc.token, `/images/${imageId}`)).image;
  if (!im) return edit("❌ اسنپ‌شات پیدا نشد.");
  const size = im.image_size ? Math.round(im.image_size * 1000) / 1000 : "—";
  const text =
    `📸 اسنپ‌شات\n\n` +
    `🏷 نام: ${code(im.name || im.description || "—")}\n` +
    `🔗 وضعیت: ${code(im.status)}\n` +
    `💾 حجم: ${code(size + " GB")}\n` +
    `📅 ساخته‌شده: ${code(im.created ? im.created.slice(0, 10) : "—")}`;
  const kb = [
    [{ text: "✏️ تغییر نام", callback_data: `hznu:${i}:${imageId}:rename` }, { text: "🗑 حذف", callback_data: `hznu:${i}:${imageId}:del` }],
    [{ text: "🔙 بازگشت", callback_data: `hzn:${i}:0` }],
  ];
  await edit(text, kb);
}

async function hzSnapshotDispatch(hzAccounts, i, imageId, step, edit, kv, chatId) {
  if (step === "rename") {
    await kv.put(`pend:${chatId}`, JSON.stringify({ type: "hz_snap_rename", acc: i, image_id: imageId }), { expirationTtl: 600 });
    return edit("✏️ نام جدید اسنپ‌شات را بفرستید:", [[{ text: "🔙 انصراف", callback_data: `hzni:${i}:${imageId}` }]]);
  }
  return edit("⚠️ مطمئنید اسنپ‌شات حذف شود؟", [
    [{ text: "✅ بله", callback_data: `hzno:${i}:${imageId}:del` }, { text: "❌ انصراف", callback_data: `hzni:${i}:${imageId}` }],
  ]);
}

async function hzSnapshotDo(hzAccounts, i, imageId, step, edit) {
  const acc = hzAccounts[i];
  if (step === "del") {
    const r = await hzFetch(acc.token, `/images/${imageId}`, { method: "DELETE" });
    if (r.error) return edit("❌ خطا: " + (r.error.message || ""));
    return edit("✅ اسنپ‌شات حذف شد.", [[{ text: "📸 اسنپ‌شات‌ها", callback_data: `hzn:${i}:0` }]]);
  }
  return edit("❓ عملیات ناشناخته.");
}

// ===================== یادآور (Reminder) UI =====================
async function renderRemindersHome(kv, edit) {
  const list = (await getReminders(kv)).slice().sort((a, b) => a.at - b.at);
  const cfg = await getRemCfg(kv);
  let text = "⏰ یادآورها\n\n";
  text += `ℹ️ راهنما: می‌تونی انقضای سرور رو همین‌جا ثبت کنی تا ${cfg.leadHours} ساعت قبل‌تر بهت اطلاع بده و از سایت مربوطه تمدید کنی.\n\n`;
  const kb = [];
  if (!list.length) {
    text += "📭 هنوز یادآوری ثبت نشده.";
  } else {
    text += `📌 ${list.length} یادآور:\n`;
    for (const r of list.slice(0, 15)) {
      const tgt = r.target && r.target.label ? ` — ${remPlain(r.target.label)}` : "";
      const when = r.kind === "expiry" && r.expiryAt ? `انقضا ${fmtJalali(r.expiryAt)}` : fmtJalali(r.at);
      text += `• ${when}${tgt}${r.text ? " — " + remPlain(r.text) : ""}\n`;
    }
    if (list.length > 15) text += `… و ${list.length - 15} مورد دیگر`;
  }
  kb.push([{ text: "➕ یادآور جدید", callback_data: "remnew" }]);
  if (list.length) kb.push([{ text: "🗑 حذف یادآور", callback_data: "remdel" }]);
  kb.push([{ text: `⚙️ تنظیمات یادآور (${cfg.leadHours} ساعت قبل)`, callback_data: "remset" }]);
  kb.push([{ text: "🔙 مانیتورها", callback_data: "mons" }, { text: "🏠 منو", callback_data: "menu" }]);
  await edit(text, kb);
}

async function renderReminderTargets(edit) {
  await edit("⏰ یادآور جدید\n\nروی چه چیزی یادآور بذارم؟", [
    [{ text: "🖥 انتخاب از سرورها (ساب‌ها)", callback_data: "remsrv" }],
    [{ text: "✍️ متن آزاد", callback_data: "remtxt" }],
    [{ text: "🔙 بازگشت", callback_data: "rem" }],
  ]);
}

async function renderReminderServers(kv, token, page, edit) {
  const servers = await kv.get(`rmsess:${token}`, "json");
  if (!Array.isArray(servers)) return edit("⏳ نشست منقضی شده.", [[{ text: "🔙 بازگشت", callback_data: "remnew" }]]);
  if (!servers.length) return edit("📭 سروری در پنل‌ها پیدا نشد.", [[{ text: "🔙 بازگشت", callback_data: "remnew" }]]);
  const per = 8;
  const pages = Math.max(1, Math.ceil(servers.length / per));
  if (page < 0) page = 0;
  if (page >= pages) page = pages - 1;
  const slice = servers.slice(page * per, page * per + per);
  const kb = [];
  for (let k = 0; k < slice.length; k++) {
    const s = slice[k];
    const gi = page * per + k;
    const ip = s.ip || "—";
    const dc = s.remark || s.panel_name || "—";
    const dcShort = dc.length > 18 ? dc.slice(0, 17) + "…" : dc;
    kb.push([
      { text: `🌐 ${ip}`, callback_data: `rempick:${token}:${gi}` },
      { text: `🖥 ${dcShort}`, callback_data: `rempick:${token}:${gi}` },
    ]);
  }
  const nav = [];
  nav.push(page > 0 ? { text: "◀️", callback_data: `rempage:${token}:${page - 1}` } : EMPTY_BTN);
  nav.push({ text: `📄 ${page + 1}/${pages}`, callback_data: "noop" });
  nav.push(page < pages - 1 ? { text: "▶️", callback_data: `rempage:${token}:${page + 1}` } : EMPTY_BTN);
  kb.push(nav);
  kb.push([{ text: "🔄 بروزرسانی", callback_data: "remsrvf" }]);
  kb.push([{ text: "🔙 بازگشت", callback_data: "remnew" }]);
  await edit("🖥 یک سرور انتخاب کنید (ستون آدرس / ستون نام):", kb);
}

// ===================== Linode UI =====================
async function showLnHome(lnAccounts, edit) {
  const kb = [];
  for (let i = 0; i < lnAccounts.length; i += 2) {
    const row = [{ text: `👤 ${lnAccounts[i].name}`, callback_data: `lnm:${i}` }];
    row.push(i + 1 < lnAccounts.length ? { text: `👤 ${lnAccounts[i + 1].name}`, callback_data: `lnm:${i + 1}` } : EMPTY_BTN);
    kb.push(row);
  }
  kb.push([{ text: "➕ افزودن اکانت لینود", callback_data: "lna" }]);
  kb.push([{ text: "🗑 حذف اکانت", callback_data: "lndel" }]);
  kb.push([{ text: "🔙 دیتاسنترها", callback_data: "providers" }, { text: "🏠 منو", callback_data: "menu" }]);
  await edit("🟢 اکانت‌های لینود\n\nیک اکانت را انتخاب کنید:", kb);
}

async function showLnAccountMenu(lnAccounts, i, edit) {
  const acc = lnAccounts[i];
  if (!acc) return edit("❌ اکانت پیدا نشد.");
  await edit(`👤 ${acc.name}\n\nانتخاب کنید:`, [
    [{ text: "🖥️ سرورها", callback_data: `lns:${i}:0` }],
    [{ text: "📸 اسنپ‌شات‌ها", callback_data: `lnn:${i}:0` }, { text: "🌐 آی‌پی‌ها", callback_data: `lnp:${i}:0` }],
    [{ text: "⚙️ تنظیمات اکانت", callback_data: `lnacc:${i}` }],
    [{ text: "🔙 اکانت‌ها", callback_data: "ln" }, { text: "🏠 منو", callback_data: "menu" }],
  ]);
}

async function showLnServers(lnAccounts, i, page, edit) {
  const acc = lnAccounts[i];
  if (!acc) return edit("❌ اکانت پیدا نشد.");
  const servers = await lnGetAll(acc.token, "/linode/instances");
  if (servers.length === 0) {
    return edit("📭 سروری یافت نشد.", [
      [{ text: "➕ ساخت سرور", callback_data: `lnsc:${i}` }],
      [{ text: "🔙 بازگشت", callback_data: `lnm:${i}` }],
    ]);
  }
  const pages = Math.ceil(servers.length / HZ_PAGE_SIZE);
  if (page < 0) page = 0;
  if (page >= pages) page = pages - 1;
  const slice = servers.slice(page * HZ_PAGE_SIZE, page * HZ_PAGE_SIZE + HZ_PAGE_SIZE);
  const kb = grid2(slice.map((s) => ({ text: lnServerListText(s), callback_data: `lnsi:${i}:${s.id}` })));
  const nav = [];
  nav.push(page > 0 ? { text: "◀️", callback_data: `lns:${i}:${page - 1}` } : EMPTY_BTN);
  nav.push({ text: `📄 ${page + 1}/${pages}`, callback_data: "noop" });
  nav.push(page < pages - 1 ? { text: "▶️", callback_data: `lns:${i}:${page + 1}` } : EMPTY_BTN);
  kb.push(nav);
  kb.push([{ text: "➕ ساخت سرور", callback_data: `lnsc:${i}` }]);
  kb.push([{ text: "🔙 بازگشت", callback_data: `lnm:${i}` }]);
  await edit(`🖥️ سرورهای «${acc.name}»:`, kb);
}

async function showLnServerInfo(lnAccounts, i, serverId, edit) {
  const acc = lnAccounts[i];
  if (!acc) return edit("❌ اکانت پیدا نشد.");
  const s = await lnFetch(acc.token, `/linode/instances/${serverId}`);
  if (!s || s.errors || !s.id) return edit("❌ سرور پیدا نشد.");
  const tr = await lnFetch(acc.token, `/linode/instances/${serverId}/transfer`);
  const used = tr && typeof tr.used === "number" ? tr.used : null;
  const quota = tr && typeof tr.quota === "number" ? tr.quota : null;
  const billable = tr && typeof tr.billable === "number" ? tr.billable : null;
  const usedPct = quota ? Math.round((used / quota) * 10) / 10 : null;
  let price = "—";
  try {
    const types = await lnGetAll(acc.token, "/linode/types");
    const t = types.find((x) => x.id === s.type);
    if (t) {
      const pr = lnRegionPrice(t, s.region);
      price = `$${pr.monthly != null ? pr.monthly : "—"}/ماه · $${pr.hourly != null ? pr.hourly : "—"}/ساعت`;
    }
  } catch (e) {}
  const specs = s.specs || {};
  const text =
    `🚀 ${code(s.label)} [${code(s.status)}]\n\n` +
    `🔗 IPv4: ${code((s.ipv4 && s.ipv4[0]) || "—")}\n` +
    `🔗 IPv6: ${code(s.ipv6 || "—")}\n` +
    `🌍 منطقه: ${code(s.region)}\n` +
    `⚙️ مشخصات: ${code(`${specs.vcpus || "?"} هسته / ${lnGb(specs.memory)}GB رم / ${lnGb(specs.disk)}GB دیسک`)}\n` +
    `🖼️ تصویر: ${code(s.image || "—")}\n` +
    `📊 ترافیک (GB):\n • مصرف: ${code(used === null ? "—" : used)}\n • سهمیه: ${code(quota === null ? "—" : quota)}\n • مازاد: ${code(billable === null ? "—" : billable)}\n • درصد: ${code(usedPct === null ? "—" : usedPct + "%")}\n` +
    `💰 قیمت: ${code(price)}`;
  const kb = grid2([
    { text: "⚡ روشن", callback_data: `lnsu:${i}:${serverId}:on` },
    { text: "🔌 خاموش", callback_data: `lnsu:${i}:${serverId}:off` },
    { text: "🔄 ریبوت", callback_data: `lnsu:${i}:${serverId}:reboot` },
    { text: "🔄 ریست", callback_data: `lnsu:${i}:${serverId}:reset` },
    { text: "🔓 ریست رمز", callback_data: `lnsu:${i}:${serverId}:pass` },
    { text: "✏️ تغییر نام", callback_data: `lnsu:${i}:${serverId}:rename` },
    { text: "🛠️ ریبیلد", callback_data: `lnsu:${i}:${serverId}:rebuild` },
    { text: "⬆️ ارتقا", callback_data: `lnsu:${i}:${serverId}:upgrade` },
    { text: "📷 اسنپ‌شات", callback_data: `lnsu:${i}:${serverId}:snap` },
    { text: "🗑 حذف اسنپ‌شات", callback_data: `lnsu:${i}:${serverId}:dsnap` },
    { text: "➕ IPv4", callback_data: `lnsu:${i}:${serverId}:a4` },
    { text: "➕ IPv6", callback_data: `lnsu:${i}:${serverId}:a6` },
    { text: "❌ IPv4", callback_data: `lnsu:${i}:${serverId}:u4` },
    { text: "❌ IPv6", callback_data: `lnsu:${i}:${serverId}:u6` },
    { text: "🗑 حذف سرور", callback_data: `lnsu:${i}:${serverId}:del` },
  ]);
  kb.push([{ text: "🔙 بازگشت", callback_data: `lns:${i}:0` }]);
  await edit(text, kb);
}

async function lnServerDispatch(lnAccounts, i, serverId, step, edit, kv, chatId) {
  const acc = lnAccounts[i];
  if (!acc) return edit("❌ اکانت پیدا نشد.");
  const s = await lnFetch(acc.token, `/linode/instances/${serverId}`);
  if (!s || !s.id) return edit("❌ سرور پیدا نشد.");
  const back = `lnsi:${i}:${serverId}`;

  if (step === "rename") {
    await kv.put(`pend:${chatId}`, JSON.stringify({ type: "ln_srv_rename", acc: i, server_id: serverId }), { expirationTtl: 600 });
    return edit("✏️ نام جدید سرور را بفرستید:", [[{ text: "🔙 انصراف", callback_data: back }]]);
  }
  if (step === "rebuild") {
    const imgs = (await lnGetAll(acc.token, "/images")).filter((x) => x.status === "available");
    if (!imgs.length) return edit("❌ تصویری پیدا نشد.", [[{ text: "🔙 بازگشت", callback_data: back }]]);
    imgs.sort((a, b) => String(a.label).localeCompare(String(b.label)));
    const kb = grid2(imgs.slice(0, 60).map((im) => ({ text: im.label, callback_data: `lnsv:${i}:${serverId}:rebuild:${im.id}` })));
    kb.push([{ text: "🔙 بازگشت", callback_data: back }]);
    return edit("🛠️ تصویر جدید برای ریبیلد:", kb);
  }
  if (step === "upgrade") {
    const types = await lnGetAll(acc.token, "/linode/types");
    const cur = s.specs || {};
    const up = types.filter((t) => t.id !== s.type && (t.memory > (cur.memory || 0) || t.vcpus > (cur.vcpus || 0) || t.disk > (cur.disk || 0)));
    if (!up.length) return edit("❌ پلن ارتقای بالاتری موجود نیست.", [[{ text: "🔙 بازگشت", callback_data: back }]]);
    up.sort((a, b) => a.memory + a.vcpus + a.disk - (b.memory + b.vcpus + b.disk));
    const kb = grid2(
      up.slice(0, 60).map((t) => {
        const pr = lnRegionPrice(t, s.region);
        return { text: `${t.label} ($${pr.monthly || "?"}/m)`, callback_data: `lnsv:${i}:${serverId}:upgrade:${t.id}` };
      })
    );
    kb.push([{ text: "🔙 بازگشت", callback_data: back }]);
    return edit("⬆️ پلن جدید را انتخاب کنید:", kb);
  }
  if (step === "dsnap") {
    const imgs = (await lnGetAll(acc.token, "/images?is_public=false")).filter((x) => x.status === "available");
    if (!imgs.length) return edit("❌ اسنپ‌شاتی برای حذف پیدا نشد.", [[{ text: "🔙 بازگشت", callback_data: back }]]);
    const kb = grid2(imgs.slice(0, 60).map((im) => ({ text: im.label, callback_data: `lnsv:${i}:${serverId}:dsnap:${im.id}` })));
    kb.push([{ text: "🔙 بازگشت", callback_data: back }]);
    return edit("🗑 اسنپ‌شات برای حذف:", kb);
  }
  const label = { on: "روشن کردن", off: "خاموش کردن", reset: "ریست", reboot: "ریبوت", pass: "ریست رمز", del: "حذف سرور", snap: "ساخت اسنپ‌شات", a4: "افزودن IPv4", a6: "افزودن IPv6", u4: "حذف IPv4", u6: "حذف IPv6" }[step];
  return edit(`⚠️ مطمئنید «${label}» روی «${s.label}» انجام شود؟`, [
    [{ text: "✅ بله", callback_data: `lnok:${i}:${serverId}:${step}` }, { text: "❌ انصراف", callback_data: back }],
  ]);
}

async function lnServerPick(lnAccounts, i, serverId, step, arg, edit) {
  const acc = lnAccounts[i];
  const s = await lnFetch(acc.token, `/linode/instances/${serverId}`);
  if (!s || !s.id) return edit("❌ سرور پیدا نشد.");
  const label = { rebuild: "ریبیلد", upgrade: "ارتقا", dsnap: "حذف اسنپ‌شات" }[step];
  return edit(`⚠️ مطمئنید «${label}» روی «${s.label}» انجام شود؟`, [
    [{ text: "✅ بله", callback_data: `lnok:${i}:${serverId}:${step}:${arg}` }, { text: "❌ انصراف", callback_data: `lnsi:${i}:${serverId}` }],
  ]);
}

async function lnServerDo(lnAccounts, i, serverId, step, arg, edit) {
  const acc = lnAccounts[i];
  const token = acc.token;
  const back = [[{ text: "🔙 بازگشت", callback_data: `lnsi:${i}:${serverId}` }]];
  const backList = [[{ text: "🖥️ سرورها", callback_data: `lns:${i}:0` }]];
  if (step === "del") {
    const r = await lnFetch(token, `/linode/instances/${serverId}`, { method: "DELETE" });
    if (r.errors) return edit("❌ خطا: " + lnErr(r));
    return edit("✅ سرور حذف شد.", backList);
  }
  if (step === "snap") {
    const s = await lnFetch(token, `/linode/instances/${serverId}`);
    const disks = await lnGetAll(token, `/linode/instances/${serverId}/disks`);
    const disk = disks.find((d) => d.filesystem && d.filesystem !== "swap") || disks[0];
    if (!disk) return edit("❌ دیسکی پیدا نشد.", back);
    const r = await lnFetch(token, "/images", { method: "POST", body: JSON.stringify({ disk_id: disk.id, label: `snap-${s.label}-${Date.now()}` }) });
    if (r.errors) return edit("❌ خطا: " + lnErr(r));
    return edit("✅ اسنپ‌شات ساخته شد.", back);
  }
  if (step === "dsnap") {
    const r = await lnFetch(token, `/images/${arg}`, { method: "DELETE" });
    if (r.errors) return edit("❌ خطا: " + lnErr(r));
    return edit("✅ اسنپ‌شات حذف شد.", back);
  }
  if (step === "a4" || step === "a6") {
    const type = step === "a4" ? "ipv4" : "ipv6";
    const r = await lnFetch(token, `/linode/instances/${serverId}/ips`, { method: "POST", body: JSON.stringify({ type, public: true }) });
    if (r.errors) return edit("❌ خطا: " + lnErr(r));
    return edit(`✅ آی‌پی ${type.toUpperCase()} اضافه شد.`, back);
  }
  if (step === "u4") {
    const s = await lnFetch(token, `/linode/instances/${serverId}`);
    const v4 = s.ipv4 || [];
    if (v4.length < 2) return edit("❌ آی‌پی IPv4 اضافه‌ای برای حذف وجود ندارد.", back);
    const address = v4[v4.length - 1];
    const r = await lnFetch(token, `/networking/ips/${encodeURIComponent(address)}`, { method: "DELETE" });
    if (r.errors) return edit("❌ خطا: " + lnErr(r));
    return edit("✅ آی‌پی حذف شد.", back);
  }
  if (step === "u6") {
    const ips = await lnGetAll(token, "/networking/ips");
    const six = ips.find((x) => x.type === "ipv6" && String(x.linode_id) === String(serverId));
    if (!six) return edit("❌ آی‌پی IPv6 قابل حذف پیدا نشد.", back);
    const r = await lnFetch(token, `/networking/ips/${encodeURIComponent(six.address)}`, { method: "DELETE" });
    if (r.errors) return edit("❌ خطا: " + lnErr(r));
    return edit("✅ آی‌پی IPv6 حذف شد.", back);
  }
  if (step === "pass") {
    const disks = await lnGetAll(token, `/linode/instances/${serverId}/disks`);
    const disk = disks.find((d) => d.filesystem && d.filesystem !== "swap") || disks[0];
    if (!disk) return edit("❌ دیسکی پیدا نشد.", back);
    const pass = lnRandomPass();
    const r = await lnFetch(token, `/linode/instances/${serverId}/disks/${disk.id}/password`, { method: "POST", body: JSON.stringify({ password: pass }) });
    if (r.errors) return edit("❌ خطا: " + lnErr(r) + "\n(برای تغییر رمز، سرور باید خاموش باشد)", back);
    return edit(`✅ رمز جدید: ${code(pass)}\n(برای اعمال، سرور را خاموش و روشن کنید)`, back);
  }
  if (step === "rebuild") {
    const pass = lnRandomPass();
    const r = await lnFetch(token, `/linode/instances/${serverId}/rebuild`, { method: "POST", body: JSON.stringify({ image: arg, root_pass: pass, booted: true }) });
    if (r.errors) return edit("❌ خطا: " + lnErr(r));
    return edit(`✅ ریبیلد شروع شد.\n🔑 رمز root: ${code(pass)}`, back);
  }
  if (step === "upgrade") {
    const r = await lnFetch(token, `/linode/instances/${serverId}/resize`, { method: "POST", body: JSON.stringify({ type: arg, allow_auto_disk_resize: true }) });
    if (r.errors) return edit("❌ خطا: " + lnErr(r));
    return edit("✅ ارتقا انجام شد.", back);
  }
  if (step === "on") {
    const r = await lnFetch(token, `/linode/instances/${serverId}/boot`, { method: "POST", body: "{}" });
    if (r.errors) return edit("❌ خطا: " + lnErr(r));
    return edit("✅ روشن شد.", back);
  }
  if (step === "off") {
    const r = await lnFetch(token, `/linode/instances/${serverId}/shutdown`, { method: "POST", body: "{}" });
    if (r.errors) return edit("❌ خطا: " + lnErr(r));
    return edit("✅ خاموش شد.", back);
  }
  if (step === "reboot" || step === "reset") {
    const r = await lnFetch(token, `/linode/instances/${serverId}/reboot`, { method: "POST", body: "{}" });
    if (r.errors) return edit("❌ خطا: " + lnErr(r));
    return edit("✅ ریبوت شد.", back);
  }
  return edit("❓ عملیات ناشناخته.");
}

async function showLnIps(lnAccounts, i, page, edit, kv) {
  const acc = lnAccounts[i];
  if (!acc) return edit("❌ اکانت پیدا نشد.");
  const ips = await lnGetAll(acc.token, "/networking/ips");
  if (ips.length === 0) {
    return edit("📭 آی‌پی‌ای یافت نشد.", [[{ text: "🔙 بازگشت", callback_data: `lnm:${i}` }]]);
  }
  const pages = Math.ceil(ips.length / HZ_PAGE_SIZE);
  if (page < 0) page = 0;
  if (page >= pages) page = pages - 1;
  const slice = ips.slice(page * HZ_PAGE_SIZE, page * HZ_PAGE_SIZE + HZ_PAGE_SIZE);
  const buttons = [];
  for (const ip of slice) {
    const token = makeToken();
    await kv.put(`lnip:${token}`, JSON.stringify({ i, address: ip.address }), { expirationTtl: 3600 });
    const tag = ip.type === "ipv4" ? "4️⃣" : "6️⃣";
    buttons.push({ text: `${tag} ${ip.address}${ip.linode_id ? " (متصل)" : ""}`, callback_data: `lnpi:${i}:${token}` });
  }
  const kb = grid2(buttons);
  const nav = [];
  nav.push(page > 0 ? { text: "◀️", callback_data: `lnp:${i}:${page - 1}` } : EMPTY_BTN);
  nav.push({ text: `📄 ${page + 1}/${pages}`, callback_data: "noop" });
  nav.push(page < pages - 1 ? { text: "▶️", callback_data: `lnp:${i}:${page + 1}` } : EMPTY_BTN);
  kb.push(nav);
  kb.push([{ text: "🔙 بازگشت", callback_data: `lnm:${i}` }]);
  await edit(`🌐 آی‌پی‌های «${acc.name}»:`, kb);
}

async function showLnIpInfo(lnAccounts, i, token, edit, kv) {
  const acc = lnAccounts[i];
  if (!acc) return edit("❌ اکانت پیدا نشد.");
  const rec = await kv.get(`lnip:${token}`, "json");
  if (!rec) return edit("⏳ نشست منقضی شده.");
  const ips = await lnGetAll(acc.token, "/networking/ips");
  const ip = ips.find((x) => x.address === rec.address);
  if (!ip) return edit("❌ آی‌پی پیدا نشد.");
  let assignee = "—";
  if (ip.linode_id) {
    const s = await lnFetch(acc.token, `/linode/instances/${ip.linode_id}`);
    if (s && s.label) assignee = s.label;
  }
  const text =
    `🌐 آی‌پی\n\n` +
    `🔗 IP: ${code(ip.address)}\n` +
    `🔤 نوع: ${code(ip.type)}\n` +
    `🌍 منطقه: ${code(ip.region || "—")}\n` +
    `🔗 متصل به: ${code(assignee)}\n` +
    `🌐 PTR: ${code(ip.rdns || "—")}`;
  const kb = grid2([
    { text: "✏️ تغییر PTR", callback_data: `lnpu:${i}:${token}:rename` },
    { text: "🔗 اختصاص به سرور", callback_data: `lnpu:${i}:${token}:assign` },
    { text: "❌ حذف اختصاص", callback_data: `lnpu:${i}:${token}:unassign` },
    { text: "🗑 حذف آی‌پی", callback_data: `lnpu:${i}:${token}:del` },
  ]);
  kb.push([{ text: "🔙 بازگشت", callback_data: `lnp:${i}:0` }]);
  await edit(text, kb);
}

async function lnIpDispatch(lnAccounts, i, token, step, edit, kv, chatId) {
  const acc = lnAccounts[i];
  const rec = await kv.get(`lnip:${token}`, "json");
  if (!acc || !rec) return edit("❌ آی‌پی پیدا نشد.");
  if (step === "rename") {
    await kv.put(`pend:${chatId}`, JSON.stringify({ type: "ln_ip_rename", acc: i, address: rec.address }), { expirationTtl: 600 });
    return edit("✏️ مقدار جدید PTR/rdns را بفرستید:", [[{ text: "🔙 انصراف", callback_data: `lnpi:${i}:${token}` }]]);
  }
  if (step === "assign") {
    const servers = await lnGetAll(acc.token, "/linode/instances");
    if (!servers.length) return edit("❌ سروری پیدا نشد.", [[{ text: "🔙 بازگشت", callback_data: `lnpi:${i}:${token}` }]]);
    const kb = grid2(servers.map((s) => ({ text: s.label, callback_data: `lnpv:${i}:${token}:assign:${s.id}` })));
    kb.push([{ text: "🔙 بازگشت", callback_data: `lnpi:${i}:${token}` }]);
    return edit("🔗 سرور مقصد را انتخاب کنید:", kb);
  }
  const label = step === "unassign" ? "حذف اختصاص آی‌پی" : "حذف آی‌پی";
  return edit(`⚠️ مطمئنید «${label}» انجام شود؟`, [
    [{ text: "✅ بله", callback_data: `lnpo:${i}:${token}:${step}` }, { text: "❌ انصراف", callback_data: `lnpi:${i}:${token}` }],
  ]);
}

async function lnIpPick(lnAccounts, i, token, step, arg, edit, kv) {
  const acc = lnAccounts[i];
  const rec = await kv.get(`lnip:${token}`, "json");
  if (!acc || !rec) return edit("❌ آی‌پی پیدا نشد.");
  const r = await lnFetch(acc.token, `/networking/ips/${encodeURIComponent(rec.address)}/assign`, {
    method: "POST",
    body: JSON.stringify({ linode_id: Number(arg) }),
  });
  if (r.errors) return edit("❌ خطا: " + lnErr(r));
  return edit("✅ آی‌پی اختصاص یافت.", [[{ text: "🔙 بازگشت", callback_data: `lnpi:${i}:${token}` }]]);
}

async function lnIpDo(lnAccounts, i, token, step, edit, kv) {
  const acc = lnAccounts[i];
  const rec = await kv.get(`lnip:${token}`, "json");
  if (!acc || !rec) return edit("❌ آی‌پی پیدا نشد.");
  const base = `/networking/ips/${encodeURIComponent(rec.address)}`;
  if (step === "del") {
    const r = await lnFetch(acc.token, base, { method: "DELETE" });
    if (r.errors) return edit("❌ خطا: " + lnErr(r));
    return edit("✅ آی‌پی حذف شد.", [[{ text: "🌐 آی‌پی‌ها", callback_data: `lnp:${i}:0` }]]);
  }
  if (step === "unassign") {
    const r = await lnFetch(acc.token, `${base}/unassign`, { method: "POST", body: "{}" });
    if (r.errors) return edit("❌ خطا: " + lnErr(r));
    return edit("✅ اختصاص حذف شد.", [[{ text: "🔙 بازگشت", callback_data: `lnpi:${i}:${token}` }]]);
  }
  return edit("❓ عملیات ناشناخته.");
}

async function showLnSnapshots(lnAccounts, i, page, edit) {
  const acc = lnAccounts[i];
  if (!acc) return edit("❌ اکانت پیدا نشد.");
  const snaps = (await lnGetAll(acc.token, "/images?is_public=false")).filter((x) => x.status === "available");
  if (snaps.length === 0) {
    return edit("📭 اسنپ‌شاتی یافت نشد.", [
      [{ text: "➕ ساخت اسنپ‌شات", callback_data: `lnnc:${i}` }],
      [{ text: "🔙 بازگشت", callback_data: `lnm:${i}` }],
    ]);
  }
  const pages = Math.ceil(snaps.length / HZ_PAGE_SIZE);
  if (page < 0) page = 0;
  if (page >= pages) page = pages - 1;
  const slice = snaps.slice(page * HZ_PAGE_SIZE, page * HZ_PAGE_SIZE + HZ_PAGE_SIZE);
  const kb = grid2(slice.map((im) => ({ text: im.label || String(im.id), callback_data: `lnni:${i}:${im.id}` })));
  const nav = [];
  nav.push(page > 0 ? { text: "◀️", callback_data: `lnn:${i}:${page - 1}` } : EMPTY_BTN);
  nav.push({ text: `📄 ${page + 1}/${pages}`, callback_data: "noop" });
  nav.push(page < pages - 1 ? { text: "▶️", callback_data: `lnn:${i}:${page + 1}` } : EMPTY_BTN);
  kb.push(nav);
  kb.push([{ text: "➕ ساخت اسنپ‌شات", callback_data: `lnnc:${i}` }]);
  kb.push([{ text: "🔙 بازگشت", callback_data: `lnm:${i}` }]);
  await edit(`📸 اسنپ‌شات‌های «${acc.name}»:`, kb);
}

async function showLnSnapshotInfo(lnAccounts, i, imageId, edit) {
  const acc = lnAccounts[i];
  const im = await lnFetch(acc.token, `/images/${imageId}`);
  if (!im || im.errors || !im.id) return edit("❌ اسنپ‌شات پیدا نشد.");
  const size = im.size ? Math.round((im.size / 1024) * 100) / 100 : "—";
  const text =
    `📸 اسنپ‌شات\n\n` +
    `🏷 نام: ${code(im.label || "—")}\n` +
    `🔗 وضعیت: ${code(im.status)}\n` +
    `💾 حجم: ${code(size + " GB")}\n` +
    `📅 ساخته‌شده: ${code(im.created ? String(im.created).slice(0, 10) : "—")}`;
  const kb = [
    [{ text: "✏️ تغییر نام", callback_data: `lnnu:${i}:${imageId}:rename` }, { text: "🗑 حذف", callback_data: `lnnu:${i}:${imageId}:del` }],
    [{ text: "🔙 بازگشت", callback_data: `lnn:${i}:0` }],
  ];
  await edit(text, kb);
}

async function lnSnapshotDispatch(lnAccounts, i, imageId, step, edit, kv, chatId) {
  if (step === "rename") {
    await kv.put(`pend:${chatId}`, JSON.stringify({ type: "ln_snap_rename", acc: i, image_id: imageId }), { expirationTtl: 600 });
    return edit("✏️ نام جدید اسنپ‌شات را بفرستید:", [[{ text: "🔙 انصراف", callback_data: `lnni:${i}:${imageId}` }]]);
  }
  return edit("⚠️ مطمئنید اسنپ‌شات حذف شود؟", [
    [{ text: "✅ بله", callback_data: `lnno:${i}:${imageId}:del` }, { text: "❌ انصراف", callback_data: `lnni:${i}:${imageId}` }],
  ]);
}

async function lnSnapshotDo(lnAccounts, i, imageId, step, edit) {
  const acc = lnAccounts[i];
  if (step === "del") {
    const r = await lnFetch(acc.token, `/images/${imageId}`, { method: "DELETE" });
    if (r.errors) return edit("❌ خطا: " + lnErr(r));
    return edit("✅ اسنپ‌شات حذف شد.", [[{ text: "📸 اسنپ‌شات‌ها", callback_data: `lnn:${i}:0` }]]);
  }
  return edit("❓ عملیات ناشناخته.");
}

// ===================== افزودن به منتخب‌ها (picker) =====================
function nameShortStr(name, zoneName) {
  if (!name) return "";
  const suffix = zoneName ? "." + zoneName : "";
  return zoneName && name.length > suffix.length && name.endsWith(suffix) ? name.slice(0, -suffix.length) : name;
}

async function favPickOpen(kv, chatId, accounts, edit, token, page) {
  const session = await kv.get(`s:${token}`, "json");
  if (!session) return edit("⏳ نشست منقضی شده.");
  const zone = await getZoneById(session.zone_id, session.acc, accounts);
  if (!zone) return edit("❌ دامنه پیدا نشد.");
  const records = await getRecords(zone, accounts, kv);
  if (!records.length) return edit(`📭 رکوردی در ${zone.name} نیست.`, [[{ text: "🔙 بازگشت", callback_data: "zones" }]]);
  const st = (await kv.get(`favpk:${chatId}`, "json")) || { token, ids: [], page: 0 };
  if (st.token !== token) return edit("⏳ نشست منقضی شده.");
  const favs = await getFavs(kv, chatId);
  const favIds = new Set(favs.filter((f) => f.zone_id === zone.id).map((f) => f.record_id));
  const chosen = new Set(st.ids || []);
  const pages = Math.ceil(records.length / RECORD_PAGE_SIZE);
  if (page === undefined || page === null) page = st.page || 0;
  if (page < 0) page = 0;
  if (page >= pages) page = pages - 1;
  st.page = page;
  const labels = duplicateLabels(records, zone.name);
  const slice = records.slice(page * RECORD_PAGE_SIZE, page * RECORD_PAGE_SIZE + RECORD_PAGE_SIZE);
  const kb = [];
  for (let i = 0; i < slice.length; i += 2) {
    const row = [];
    for (let j = i; j < i + 2; j++) {
      if (j < slice.length) {
        const r = slice[j];
        const mark = favIds.has(r.id) ? "⭐" : chosen.has(r.id) ? "✅" : "⬜";
        row.push({ text: `${mark} ${labels[r.id]}`, callback_data: `favpsel:${token}:${r.id}` });
      } else {
        row.push(EMPTY_BTN);
      }
    }
    kb.push(row);
  }
  const nav = [];
  nav.push(page > 0 ? { text: "◀️", callback_data: `favpp:${token}:${page - 1}` } : EMPTY_BTN);
  nav.push({ text: `📄 ${page + 1}/${pages}`, callback_data: "noop" });
  nav.push(page < pages - 1 ? { text: "▶️", callback_data: `favpp:${token}:${page + 1}` } : EMPTY_BTN);
  kb.push(nav);
  kb.push([
    { text: `✅ ذخیره (${(st.ids || []).length})`, callback_data: `favpsave:${token}` },
    { text: "❌ لغو", callback_data: `favpcancel:${token}` },
  ]);
  await edit(
    `⭐ افزودن به منتخب‌ها — ${zone.name}\n\nروی ساب‌ها بزنید (⬜ → ✅). ⭐ یعنی از قبل منتخب است.\nبرای حذف از منتخب‌ها، از صفحهٔ «⭐ ساب‌های منتخب» استفاده کنید.`,
    kb
  );
}

async function favPickZoneScreen(kv, accounts, edit) {
  const zones = await getAllZones(accounts, kv);
  const kb = grid2(
    zones.map((z) => ({ text: `📁 ${z.name}`, callback_data: `favz:${z._acc}:${z.id}` }))
  );
  kb.push([{ text: "🔙 ساب‌های منتخب", callback_data: "favs" }]);
  kb.push([{ text: "🏠 منو", callback_data: "menu" }]);
  await edit(zones.length ? "دامنه‌ای را که می‌خواهید از رکوردهایش به منتخب اضافه کنید انتخاب کنید:" : "📭 دامنه‌ای یافت نشد.", kb);
}

async function showBulkSelect(kv, accounts, edit, token, zone, page, selected) {
  const records = await getRecords(zone, accounts, kv);
  const pages = Math.ceil(records.length / RECORD_PAGE_SIZE);
  if (page < 0) page = 0;
  if (page >= pages) page = pages - 1;
  const slice = records.slice(page * RECORD_PAGE_SIZE, page * RECORD_PAGE_SIZE + RECORD_PAGE_SIZE);
  const selSet = new Set(selected || []);
  const labels = duplicateLabels(records, zone.name);
  const kb = [];
  for (let i = 0; i < slice.length; i += 3) {
    const row = [];
    for (let j = i; j < i + 3; j++) {
      if (j < slice.length) {
        const r = slice[j];
        const mark = selSet.has(r.id) ? "✅" : "⬜";
        row.push({ text: `${mark} ${labels[r.id]}`, callback_data: `bulksel:${token}:${r.id}` });
      } else {
        row.push(EMPTY_BTN);
      }
    }
    kb.push(row);
  }
  if (selSet.size > 0) {
    kb.push([
      { text: `✅ ${selSet.size} انتخاب`, callback_data: "noop" },
      { text: "🗑 حذف انتخاب‌ها", callback_data: `bulkdel:${token}` },
      { text: "✏️ تغییر مقدار", callback_data: `bulkedit:${token}` },
    ]);
    kb.push([{ text: "🔄 تغییر نوع", callback_data: `bulktype:${token}` }, { text: "❌ لغو انتخاب", callback_data: `bulkdne:${token}` }]);
  } else {
    kb.push([{ text: "❌ لغو انتخاب", callback_data: `bulkdne:${token}` }]);
  }
  const nav = [];
  nav.push(page > 0 ? { text: "◀️", callback_data: `bulkp:${token}:${page - 1}` } : EMPTY_BTN);
  nav.push({ text: `📄 ${page + 1}/${pages}`, callback_data: "noop" });
  nav.push(page < pages - 1 ? { text: "▶️", callback_data: `bulkp:${token}:${page + 1}` } : EMPTY_BTN);
  kb.push(nav);
  await edit(`🗂 ${zone.name} — ${selSet.size} انتخاب شده`, kb);
}

// ===================== تغییر سریع (فرستادن IP / نام در چت) =====================
async function sendQuickIpMenu(chatId, ip, kv, accounts, send) {
  const favs = await getFavs(kv, chatId);
  const lines = ["⚡ تغییر سریع\n", `🎯 IP جدید: ${code(ip)}`, ""];
  const kb = [];
  if (favs.length) {
    lines.push("روی یک سابِ منتخب بزنید:");
    for (let i = 0; i < favs.length; i++) {
      const f = favs[i];
      kb.push([{ text: `⚡ ${favTypeShort(f)} ${favShortName(f)} — ${f.zone_name}`, callback_data: `qafav:${i}` }]);
    }
    lines.push("");
  } else {
    lines.push("📭 سابِ منتخبی ندارید. از «🔍 جستجو در دامنه‌ها» استفاده کنید یا ابتدا ساب‌ها را ⭐ کنید.");
  }
  lines.push("یا نام ساب‌دامین را تایپ کنید تا جستجو و انتخاب کنید.");
  kb.push([{ text: "🔍 جستجو در دامنه‌ها", callback_data: "qasearch" }]);
  kb.push([{ text: "❌ لغو", callback_data: "qacancel" }]);
  await send(lines.join("\n"), kb);
}

async function renderQuickResults(token, results, query, qa, send) {
  if (!results.length) {
    const kb = qa && qa.ip
      ? [[{ text: "🔙 انتخاب سریع", callback_data: "qamenu" }], [{ text: "🏠 منو", callback_data: "menu" }]]
      : [[{ text: "🏠 منو", callback_data: "menu" }]];
    return send(`🔍 نتیجه‌ای برای «${escHtml(query)}» پیدا نشد.`, kb);
  }
  const slice = results.slice(0, 10);
  const lines = [`🔍 نتایج «${escHtml(query)}» (${results.length}):`, ""];
  const kb = [];
  for (let i = 0; i < slice.length; i++) {
    const res = slice[i];
    const short = nameShortStr(res.record.name, res.zone_name);
    const label = `${res.record.type} ${short}`;
    lines.push(`${i + 1}) ${label}\n   → ${code(res.record.content)}  [${code(res.zone_name)}]`);
    kb.push([{ text: qa && qa.ip ? `⚡ ${label}` : `✏️ ${label}`, callback_data: qa && qa.ip ? `qasel:${token}:${i}` : `qn:${token}:${i}` }]);
  }
  kb.push([{ text: "🏠 منو", callback_data: "menu" }]);
  await send(lines.join("\n"), kb);
}

async function quickNameSearch(text, qa, chatId, accounts, send, kv) {
  const results = await searchRecords(accounts, "name", text, null, kv);
  const token = makeToken();
  await kv.put(`sr:${token}`, JSON.stringify({ field: "name", query: text, results }), { expirationTtl: 3600 });
  await renderQuickResults(token, results, text, qa, send);
}

async function qaConfirmText(qa, rec) {
  return (
    `⚡ تأیید تغییر\n\n` +
    `📛 ساب‌دامین: ${code(rec.name)}\n` +
    `📁 دامنه: ${code(qa.zone_name || "؟")}\n` +
    `🔴 قبلی: ${code(rec.content)}\n` +
    `🟢 جدید: ${code(qa.ip)}\n\n` +
    `اعمال شود؟`
  );
}

async function showQaConfirm(io) {
  const { kv, chatId, messageId, accounts, botToken, edit } = io;
  const qa = await kv.get(`qa:${chatId}`, "json");
  if (!qa || !qa.record_id) {
    await edit("⏳ انتخاب منقضی شد. دوباره IP را بفرستید.", mainMenuKeyboard());
    return true;
  }
  const rec = await getRecordById(qa.acc, qa.zone_id, qa.record_id, accounts);
  if (!rec) {
    await kv.delete(`qa:${chatId}`);
    await edit("❌ رکورد پیدا نشد (شاید حذف شده).", [[{ text: "🏠 منو", callback_data: "menu" }]]);
    return true;
  }
  await edit(await qaConfirmText(qa, rec), [
    [{ text: "✅ تأیید و اعمال", callback_data: "qaok" }, { text: "❌ لغو", callback_data: "qacancel" }],
  ]);
  return true;
}

async function qaApply(io) {
  const { kv, chatId, messageId, accounts, botToken, edit } = io;
  const qa = await kv.get(`qa:${chatId}`, "json");
  if (!qa || !qa.record_id) {
    await edit("⏳ انتخاب منقضی شد.", [[{ text: "🏠 منو", callback_data: "menu" }]]);
    return true;
  }
  const prev = await getRecordById(qa.acc, qa.zone_id, qa.record_id, accounts);
  if (!prev) {
    await kv.delete(`qa:${chatId}`);
    await edit("❌ رکورد پیدا نشد (شاید حذف شده).", [[{ text: "🏠 منو", callback_data: "menu" }]]);
    return true;
  }
  const res = await fetch(`${CF_API}/zones/${qa.zone_id}/dns_records/${qa.record_id}`, {
    method: "PATCH",
    headers: hdr(accounts[qa.acc].token),
    body: JSON.stringify({ content: qa.ip }),
    signal: withTimeout(),
  });
  const data = await res.json();
  if (!data.success) {
    await edit("❌ خطا:\n" + cfErrText(data));
    return true;
  }
  await invalidateCache(kv, qa.zone_id);
  await kv.delete(`qa:${chatId}`);
  const sum = diffSummary(data.result.name, prev.content, data.result.content);
  await edit(sum, []);
  await sleep(2000);
  await redrawMenuNav(kv, botToken, chatId, messageId);
  return true;
}

async function dispatchFavQa(data, io) {
  const { kv, chatId, messageId, accounts, botToken, edit, send } = io;

  if (data === "favs") {
    await renderFavsScreen(kv, chatId, accounts, edit);
    return true;
  }
  if (data === "bulk_main") {
    const zones = await getAllZones(accounts, kv);
    if (zones.length === 0) return edit("📭 هیچ دامنه‌ای نیست.", [[{ text: "🏠 منو", callback_data: "menu" }]]);
    const kb = zones.map((z) => [{ text: `${z.status === "active" ? "🟢" : "⚪"} ${z.name}`, callback_data: `bulkz:${z._acc}:${z.id}` }]);
    kb.push([{ text: "🏠 منو", callback_data: "menu" }]);
    await edit("🗂 عملیات گروهی\n\nروی دامنه‌ای که می‌خواهید رکوردها را انتخاب کنید کلیک کنید:", kb);
    return true;
  }
  if (data === "favpickzone") {
    await favPickZoneScreen(kv, accounts, edit);
    return true;
  }
  if (data.startsWith("bulkz:")) {
    const parts = data.split(":");
    const accIndex = Number(parts[1]);
    const zoneId = parts[2];
    const zone = await getZoneById(zoneId, accIndex, accounts);
    if (!zone) return edit("❌ دامنه پیدا نشد.");
    const token = makeToken();
    await kv.put(`s:${token}`, JSON.stringify({ zone_id: zone.id, zone_name: zone.name, acc: accIndex, bpage: 0, zback: "bulk_main" }), { expirationTtl: 86400 });
    await showBulkSelect(kv, accounts, edit, token, zone, 0);
    return true;
  }
  if (data.startsWith("favz:")) {
    const parts = data.split(":");
    const accIndex = Number(parts[1]);
    const zoneId = parts[2];
    const zone = await getZoneById(zoneId, accIndex, accounts);
    if (!zone) return edit("❌ دامنه پیدا نشد.");
    const token = makeToken();
    await kv.put(`s:${token}`, JSON.stringify({ zone_id: zone.id, zone_name: zone.name, acc: accIndex }), { expirationTtl: 86400 });
    await kv.put(`favpk:${chatId}`, JSON.stringify({ token, ids: [], page: 0 }), { expirationTtl: 3600 });
    await favPickOpen(kv, chatId, accounts, edit, token, 0);
    return true;
  }
  if (data.startsWith("favpick:")) {
    const token = data.slice(8);
    const session = await kv.get(`s:${token}`, "json");
    if (!session) return edit("⏳ نشست منقضی شده.");
    await kv.put(`favpk:${chatId}`, JSON.stringify({ token, ids: [], page: 0 }), { expirationTtl: 3600 });
    await favPickOpen(kv, chatId, accounts, edit, token, 0);
    return true;
  }
  if (data.startsWith("favpsel:")) {
    const parts = data.split(":");
    const token = parts[1];
    const recordId = parts[2];
    const st = (await kv.get(`favpk:${chatId}`, "json")) || { token, ids: [], page: 0 };
    if (st.token !== token) return edit("⏳ نشست منقضی شده.");
    const session = await kv.get(`s:${token}`, "json");
    if (!session) return edit("⏳ نشست منقضی شده.");
    const ids = st.ids || [];
    const idx = ids.indexOf(recordId);
    if (idx >= 0) ids.splice(idx, 1);
    else if (!favExists(await getFavs(kv, chatId), session.zone_id, recordId)) ids.push(recordId);
    st.ids = ids;
    await kv.put(`favpk:${chatId}`, JSON.stringify(st), { expirationTtl: 3600 });
    await favPickOpen(kv, chatId, accounts, edit, token, st.page || 0);
    return true;
  }
  if (data.startsWith("favpp:")) {
    const parts = data.split(":");
    const token = parts[1];
    const page = Number(parts[2]) || 0;
    const st = (await kv.get(`favpk:${chatId}`, "json")) || { token, ids: [], page: 0 };
    if (st.token !== token) return edit("⏳ نشست منقضی شده.");
    st.page = page;
    await kv.put(`favpk:${chatId}`, JSON.stringify(st), { expirationTtl: 3600 });
    await favPickOpen(kv, chatId, accounts, edit, token, page);
    return true;
  }
  if (data.startsWith("favpcancel:")) {
    const token = data.slice(11);
    await kv.delete(`favpk:${chatId}`);
    await redrawRecordsList(kv, accounts, botToken, chatId, messageId, token, 0);
    return true;
  }
  if (data.startsWith("favpsave:")) {
    const token = data.slice(9);
    const session = await kv.get(`s:${token}`, "json");
    if (!session) return edit("⏳ نشست منقضی شده.");
    const st = (await kv.get(`favpk:${chatId}`, "json")) || { token, ids: [] };
    if (st.token !== token) return edit("⏳ نشست منقضی شده.");
    await kv.delete(`favpk:${chatId}`);
    const favs = await getFavs(kv, chatId);
    let added = 0;
    for (const rid of st.ids || []) {
      if (favExists(favs, session.zone_id, rid)) continue;
      const rec = await getRecordById(session.acc, session.zone_id, rid, accounts);
      if (!rec) continue;
      favs.push({ zone_id: session.zone_id, zone_name: session.zone_name, acc: session.acc, record_id: rid, name: rec.name, type: rec.type });
      added++;
    }
    await saveFavs(kv, chatId, favs);
    await edit(`✅ ${added} ساب به منتخب‌ها اضافه شد.`, []);
    await sleep(2000);
    await redrawRecordsList(kv, accounts, botToken, chatId, messageId, token, 0);
    return true;
  }
  if (data === "favdel") {
    const favs = await getFavs(kv, chatId);
    if (!favs.length) return edit("📭 سابی در منتخب‌ها نیست.", [[{ text: "⭐ ساب‌های منتخب", callback_data: "favs" }]]);
    const kb = favs.map((f, i) => [{ text: `🗑 ${favTypeShort(f)} ${favShortName(f)} — ${f.zone_name}`, callback_data: `favdelx:${i}` }]);
    kb.push([{ text: "🔙 ساب‌های منتخب", callback_data: "favs" }]);
    await edit("🗑 کدام ساب از منتخب‌ها حذف شود؟", kb);
    return true;
  }
  if (data.startsWith("favdelx:")) {
    const i = Number(data.slice(8));
    const favs = await getFavs(kv, chatId);
    if (!favs[i]) return edit("❌ ساب پیدا نشد.");
    favs.splice(i, 1);
    await saveFavs(kv, chatId, favs);
    await renderFavsScreen(kv, chatId, accounts, edit);
    return true;
  }
  if (data.startsWith("favtg:")) {
    const parts = data.split(":");
    const token = parts[1];
    const recordId = parts[2];
    const session = await kv.get(`s:${token}`, "json");
    if (!session) return edit("⏳ نشست منقضی شده.");
    const favs = await getFavs(kv, chatId);
    const zoneIdForFav = session.provider === "arvan" ? "arvan:" + session.domain : session.zone_id;
    const zoneNameForFav = session.provider === "arvan" ? session.domain : session.zone_name;
    if (favExists(favs, zoneIdForFav, recordId)) {
      const keep = favs.filter((f) => !(f.zone_id === zoneIdForFav && f.record_id === recordId));
      await saveFavs(kv, chatId, keep);
    } else {
      let rec;
      if (session.provider === "arvan") {
        const records = await arvanGetAllRecords(await arvanToken(kv, session.acc), session.domain);
        rec = records.find((r) => r.id === recordId);
      } else {
        rec = await getRecordById(session.acc, session.zone_id, recordId, accounts);
      }
      if (!rec) return edit("❌ رکورد پیدا نشد.");
      favs.push({ zone_id: zoneIdForFav, zone_name: zoneNameForFav, acc: session.acc, record_id: recordId, name: rec.name, type: rec.type });
      await saveFavs(kv, chatId, favs);
    }
    const nav = (await kv.get(`dd:${chatId}:${messageId}`, "json")) || { token, recordId, backCb: `rback:${token}` };
    await renderRecordDetail(kv, accounts, edit, chatId, token, recordId, nav.backCb);
    return true;
  }
  if (data.startsWith("bulksel:")) {
    const parts = data.split(":");
    const token = parts[1];
    const recordId = parts[2];
    let selected = await kv.get(`sel:${chatId}`, "json");
    if (!Array.isArray(selected)) selected = [];
    const idx = selected.indexOf(recordId);
    if (idx >= 0) selected.splice(idx, 1);
    else selected.push(recordId);
    await kv.put(`sel:${chatId}`, JSON.stringify(selected));
    const session = await kv.get(`s:${token}`, "json");
    if (!session) return edit("⏳ نشست منقضی شده.");
    const zone = await getZoneById(session.zone_id, session.acc, accounts);
    await showBulkSelect(kv, accounts, edit, token, zone, Number(session.bpage) || 0, selected);
    return true;
  }
  if (data.startsWith("bulkdne:")) {
    await kv.delete(`sel:${chatId}`);
    const token = data.slice(8);
    const session = await kv.get(`s:${token}`, "json");
    if (!session) return edit("⏳ نشست منقضی شده.", [[{ text: "🏠 منو", callback_data: "menu" }]]);
    const zone = await getZoneById(session.zone_id, session.acc, accounts);
    const records = await getRecords(zone, accounts, kv);
    await renderRecords(zone, records, token, Number(session.bpage) || 0, edit, undefined, session.zback);
    return true;
  }
  if (data.startsWith("bulkp:")) {
    const parts = data.split(":");
    const token = parts[1];
    const page = Number(parts[2]);
    const session = await kv.get(`s:${token}`, "json");
    if (!session) return edit("⏳ نشست منقضی شده.");
    session.bpage = page;
    await kv.put(`s:${token}`, JSON.stringify(session), { expirationTtl: 86400 });
    const zone = await getZoneById(session.zone_id, session.acc, accounts);
    let selected = await kv.get(`sel:${chatId}`, "json");
    if (!Array.isArray(selected)) selected = [];
    await showBulkSelect(kv, accounts, edit, token, zone, page, selected);
    return true;
  }
  if (data.startsWith("bulkdel:")) {
    const token = data.slice(8);
    const selected = await kv.get(`sel:${chatId}`, "json");
    if (!Array.isArray(selected) || selected.length === 0) {
      await kv.delete(`sel:${chatId}`);
      return edit("❌ هیچ رکوردی انتخاب نشده.", [[{ text: "🏠 منو", callback_data: "menu" }]]);
    }
    const session = await kv.get(`s:${token}`, "json");
    if (!session) return edit("⏳ نشست منقضی شده.");
    await kv.put(`pend:${chatId}`, JSON.stringify({ type: "bulk_del", ids: selected, zone_id: session.zone_id, acc: session.acc, token, msgId: messageId }), { expirationTtl: 600 });
    await edit(`⚠️ ${selected.length} رکورد انتخاب شده. مطمئنید حذف شوند؟`, [
      [{ text: "✅ بله، حذف کن", callback_data: `bulkdely:${token}` }, { text: "❌ انصراف", callback_data: `bulkdne:${token}` }],
    ]);
    return true;
  }
  if (data.startsWith("bulkdely:")) {
    const token = data.slice(9);
    const selected = await kv.get(`sel:${chatId}`, "json");
    if (!Array.isArray(selected) || selected.length === 0) {
      await kv.delete(`sel:${chatId}`);
      return edit("❌ هیچ رکوردی انتخاب نشده.", [[{ text: "🏠 منو", callback_data: "menu" }]]);
    }
    const session = await kv.get(`s:${token}`, "json");
    if (!session) return edit("⏳ نشست منقضی شده.");
    let ok = 0;
    for (const id of selected) {
      const del = await fetch(`${CF_API}/zones/${session.zone_id}/dns_records/${id}`, {
        method: "DELETE",
        headers: hdr(accounts[session.acc].token),
        signal: withTimeout(),
      });
      const d = await del.json();
      if (d.success) ok++;
    }
    await invalidateCache(kv, session.zone_id);
    await kv.delete(`sel:${chatId}`);
    await edit(`✅ ${ok} از ${selected.length} رکورد حذف شد.`, [[{ text: "🏠 منو", callback_data: "menu" }]]);
    return true;
  }
  if (data.startsWith("bulkedit:")) {
    const token = data.slice(9);
    const selected = await kv.get(`sel:${chatId}`, "json");
    if (!Array.isArray(selected) || selected.length === 0) {
      await kv.delete(`sel:${chatId}`);
      return edit("❌ هیچ رکوردی انتخاب نشده.", [[{ text: "🏠 منو", callback_data: "menu" }]]);
    }
    const session = await kv.get(`s:${token}`, "json");
    if (!session) return edit("⏳ نشست منقضی شده.");
    await kv.put(`pend:${chatId}`, JSON.stringify({ type: "bulk_edit", ids: selected, zone_id: session.zone_id, acc: session.acc, token, msgId: messageId }), { expirationTtl: 600 });
    await edit("✏️ مقدار جدید را بفرستید:", [[{ text: "❌ انصراف", callback_data: `bulkdne:${token}` }]]);
    return true;
  }
  if (data.startsWith("bulktype:")) {
    const token = data.slice(9);
    const selected = await kv.get(`sel:${chatId}`, "json");
    if (!Array.isArray(selected) || selected.length === 0) {
      await kv.delete(`sel:${chatId}`);
      return edit("❌ هیچ رکوردی انتخاب نشده.", [[{ text: "🏠 منو", callback_data: "menu" }]]);
    }
    const session = await kv.get(`s:${token}`, "json");
    if (!session) return edit("⏳ نشست منقضی شده.");
    await kv.put(`pend:${chatId}`, JSON.stringify({ type: "bulk_type", ids: selected, zone_id: session.zone_id, acc: session.acc, token, msgId: messageId }), { expirationTtl: 600 });
    const kb = RECORD_TYPES.map((t) => [{ text: `به ${t}`, callback_data: `bulkty:${token}:${t}` }]);
    kb.push([{ text: "❌ انصراف", callback_data: `bulkdne:${token}` }]);
    await edit("🔄 نوع جدید را انتخاب کنید:", kb);
    return true;
  }
  if (data.startsWith("bulkty:")) {
    const parts = data.split(":");
    const token = parts[1];
    const newType = parts[2];
    const selected = await kv.get(`sel:${chatId}`, "json");
    if (!Array.isArray(selected) || selected.length === 0) {
      await kv.delete(`sel:${chatId}`);
      return edit("❌ هیچ رکوردی انتخاب نشده.", [[{ text: "🏠 منو", callback_data: "menu" }]]);
    }
    const session = await kv.get(`s:${token}`, "json");
    if (!session) return edit("⏳ نشست منقضی شده.");
    await kv.put(`pend:${chatId}`, JSON.stringify({ type: "bulk_type_convert", new_type: newType, ids: selected, zone_id: session.zone_id, acc: session.acc, token, msgId: messageId }), { expirationTtl: 600 });
    await edit(`🔄 مقدار جدید را برای نوع ${newType} بفرستید:`, [[{ text: "❌ انصراف", callback_data: `bulkdne:${token}` }]]);
    return true;
  }
  if (data.startsWith("favopen:")) {
    const i = Number(data.slice(8));
    const favs = await getFavs(kv, chatId);
    const f = favs[i];
    if (!f) return edit("❌ ساب پیدا نشد.", [[{ text: "⭐ ساب‌های منتخب", callback_data: "favs" }]]);
    const token = makeToken();
    await kv.put(`s:${token}`, JSON.stringify({ zone_id: f.zone_id, zone_name: f.zone_name, acc: f.acc }), { expirationTtl: 86400 });
    await kv.put(`dd:${chatId}:${messageId}`, JSON.stringify({ token, recordId: f.record_id, backCb: "favs" }), { expirationTtl: 86400 });
    await renderRecordDetail(kv, accounts, edit, chatId, token, f.record_id, "favs");
    return true;
  }

  // ===== تغییر سریع =====
  if (data === "qamenu") {
    const qa = await kv.get(`qa:${chatId}`, "json");
    if (qa && qa.ip) await sendQuickIpMenu(chatId, qa.ip, kv, accounts, send);
    else await edit(mainMenuText(), mainMenuKeyboard());
    return true;
  }
  if (data === "qasearch") {
    await kv.put(`pend:${chatId}`, JSON.stringify({ type: "qa_search", msgId: messageId }), { expirationTtl: 600 });
    await edit("🔍 نام ساب‌دامین یا بخشی از آن را بفرستید:", [[{ text: "❌ لغو", callback_data: "qacancel" }]]);
    return true;
  }
  if (data === "qacancel") {
    await kv.delete(`qa:${chatId}`);
    await kv.delete(`pend:${chatId}`);
    await edit(mainMenuText(), mainMenuKeyboard());
    return true;
  }
  if (data.startsWith("qafav:")) {
    const i = Number(data.slice(6));
    const favs = await getFavs(kv, chatId);
    const f = favs[i];
    const qa = await kv.get(`qa:${chatId}`, "json");
    if (!f || !qa || !qa.ip) {
      await edit("⏳ انتخاب منقضی شد. دوباره IP را بفرستید.", mainMenuKeyboard());
      return true;
    }
    await kv.put(`qa:${chatId}`, JSON.stringify({ ip: qa.ip, zone_id: f.zone_id, zone_name: f.zone_name, acc: f.acc, record_id: f.record_id }), { expirationTtl: 3600 });
    await showQaConfirm(io);
    return true;
  }
  if (data.startsWith("qasel:")) {
    const parts = data.split(":");
    const token = parts[1];
    const idx = Number(parts[2]);
    const stored = await kv.get(`sr:${token}`, "json");
    const qa = await kv.get(`qa:${chatId}`, "json");
    if (!stored || !stored.results[idx] || !qa || !qa.ip) {
      await edit("⏳ نشست منقضی شد.", mainMenuKeyboard());
      return true;
    }
    const res = stored.results[idx];
    await kv.put(`qa:${chatId}`, JSON.stringify({ ip: qa.ip, zone_id: res.zone_id, zone_name: res.zone_name, acc: res.acc, record_id: res.record.id }), { expirationTtl: 3600 });
    await showQaConfirm(io);
    return true;
  }
  if (data.startsWith("qn:")) {
    const parts = data.split(":");
    const token = parts[1];
    const idx = Number(parts[2]);
    const stored = await kv.get(`sr:${token}`, "json");
    if (!stored || !stored.results[idx]) return edit("⏳ نشست منقضی شده.");
    const res = stored.results[idx];
    await kv.put(
      `pend:${chatId}`,
      JSON.stringify({ type: "qa_value", zone_id: res.zone_id, zone_name: res.zone_name, record_id: res.record.id, acc: res.acc, msgId: messageId }),
      { expirationTtl: 600 }
    );
    await edit(`✏️ ${code(res.record.name)}\n\nآی‌پی جدیدی که می‌خواهید اعمال شود را بفرستید:`, [
      [{ text: "❌ لغو", callback_data: "qacancel" }],
    ]);
    return true;
  }
  if (data === "qaok") {
    await qaApply(io);
    return true;
  }
  return false;
}

// ===================== Host Anti-Filter Monitor (PasarGuard hosts) =====================
// Every run: read PasarGuard hosts, ping each domain from Iranian check-host nodes.
// If >= cityThreshold Iranian cities report 0 successful pings (twice in a row), the
// domain is considered filtered in Iran and is swapped for a freshly created numbered
// subdomain (mirroring the original DNS record), then written back into the host.
const CHECK_HOST_API = "https://check-host.net";
const IR_CHECK_NODES = [
  { id: "ir1.node.check-host.net", city: "Tehran" },
  { id: "ir5.node.check-host.net", city: "Tehran" },
  { id: "ir7.node.check-host.net", city: "Tehran" },
  { id: "ir8.node.check-host.net", city: "Tehran" },
  { id: "ir2.node.check-host.net", city: "Isfahan" },
  { id: "ir3.node.check-host.net", city: "Shiraz" },
  { id: "ir4.node.check-host.net", city: "Shiraz" },
];
const HOSTFILTER_FALLBACK_ROOTS = ["pcapps.ir", "app9.ir"];
const IR_CITIES = ["Tehran", "Isfahan", "Shiraz"];
const HOSTFILTER_DEFAULT_CITIES = 2;
const HOSTFILTER_DEFAULT_BATCH = 60;
const HOSTFILTER_MAX_LOG = 40;

async function getHostFilterCfg(kv) {
  let cfg = await kvGetCached(kv, "host_filter_cfg", "json", 30000);
  if (!cfg || typeof cfg !== "object") cfg = {};
  let sel = Array.isArray(cfg.citiesSel) ? cfg.citiesSel.filter((c) => IR_CITIES.includes(c)) : [];
  if (!sel.length) sel = IR_CITIES.slice();
  return {
    enabled: cfg.enabled !== false,
    provider: cfg.provider === "checkhost" ? "checkhost" : "globalping",
    intervalMin: Math.max(1, Number(cfg.intervalMin) || 11),
    cities: Math.min(Math.max(1, Number(cfg.cities) || HOSTFILTER_DEFAULT_CITIES), sel.length),
    citiesSel: sel,
    maxOk: Number.isInteger(cfg.maxOk) ? Math.max(0, Math.min(3, cfg.maxOk)) : 0,
    probes: Math.max(1, Math.min(50, Number(cfg.probes) || 50)),
    minFail: Math.max(1, Math.min(5, Number(cfg.minFail) || 2)),
    gpToken: cfg.gpToken || "",
    exceptions: Array.isArray(cfg.exceptions) ? cfg.exceptions : [],
    batch: Math.max(1, Math.min(60, Number(cfg.batch) || HOSTFILTER_DEFAULT_BATCH)),
    maxChanges: Math.max(1, Math.min(20, Number(cfg.maxChanges) || 8)),
    backupKeep: Math.max(1, Math.min(10, Number(cfg.backupKeep) || 5)),
    cursor: Number(cfg.cursor) || 0,
    last_run: cfg.last_run || null,
    last_attempt: cfg.last_attempt || null,
    last_summary: cfg.last_summary || null,
    checkhost_down: cfg.checkhost_down || null,
    manual_request: cfg.manual_request || null,
  };
}

async function saveHostFilterCfg(kv, cfg) {
  await kvPutCached(kv, "host_filter_cfg", JSON.stringify(cfg), undefined, 30000);
}

async function getHostStateAll(kv) {
  const s = await kvGetCached(kv, "host_filter_state", "json", 30000);
  return s && typeof s === "object" ? JSON.parse(JSON.stringify(s)) : {};
}

async function saveHostStateAll(kv, s) {
  await kvPutCached(kv, "host_filter_state", JSON.stringify(s), undefined, 30000);
}

async function hostFilterLog(kv, entry) {
  let log = await kvGetCached(kv, "host_filter_log", "json", 30000);
  if (!Array.isArray(log)) log = [];
  log = log.slice();
  log.unshift(entry);
  if (log.length > HOSTFILTER_MAX_LOG) log = log.slice(0, HOSTFILTER_MAX_LOG);
  await kvPutCached(kv, "host_filter_log", JSON.stringify(log), undefined, 30000);
}

function isDomainLike(v) {
  return typeof v === "string" && /^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/i.test(v) && !/^\d{1,3}(\.\d{1,3}){3}$/.test(v);
}

function pingAttempts(raw) {
  const out = [];
  const walk = (x) => {
    if (!Array.isArray(x)) return;
    if (x.length && (typeof x[0] === "string" || x[0] === null)) {
      out.push(x);
      return;
    }
    for (const y of x) walk(y);
  };
  walk(raw);
  return out;
}

async function checkHostPing(target, citySel, env) {
  const cities = Array.isArray(citySel) && citySel.length ? citySel : IR_CITIES;
  const relay = env && env.HF_RELAY_URL ? String(env.HF_RELAY_URL).replace(/\/+$/, "") : "";
  if (relay) {
    let rres;
    try {
      rres = await fetch(
        `${relay}/check?token=${encodeURIComponent((env && env.HF_RELAY_TOKEN) || "")}&target=${encodeURIComponent(target)}&cities=${encodeURIComponent(cities.join(","))}`,
        { headers: { accept: "application/json" }, signal: withTimeout(70000) }
      );
    } catch (e) {
      return { error: "relay_fetch" };
    }
    if (!rres.ok) return { error: `relay_http_${rres.status}` };
    let rd;
    try {
      rd = await rres.json();
    } catch (e) {
      return { error: "relay_json" };
    }
    if (!rd || rd.error || !rd.nodes) return { error: rd && rd.error ? `relay_${rd.error}` : "relay_api" };
    return { nodes: rd.nodes };
  }
  const nodes = IR_CHECK_NODES.filter((n) => cities.includes(n.city));
  if (!nodes.length) return { error: "no_city" };
  let res;
  try {
    const qs = nodes.map((n) => `&node=${encodeURIComponent(n.id)}`).join("");
    res = await fetch(`${CHECK_HOST_API}/check-ping?host=${encodeURIComponent(target)}${qs}`, {
      headers: { accept: "application/json", "user-agent": "Mozilla/5.0" },
      signal: withTimeout(20000),
    });
  } catch (e) {
    return { error: "fetch" };
  }
  if (!res.ok) {
    let body = "";
    try {
      body = (await res.text()).replace(/\s+/g, " ").substring(0, 160);
    } catch (e) {}
    return { error: `http_${res.status} ${body}` };
  }
  let data;
  try {
    data = await res.json();
  } catch (e) {
    return { error: "bad_json" };
  }
  if (!data || data.ok !== 1 || !data.request_id) return { error: "api" };
  const rid = data.request_id;
  let out = null;
  for (let attempt = 0; attempt < 4; attempt++) {
    await sleep(attempt === 0 ? 6000 : 3500);
    let rres;
    try {
      rres = await fetch(`${CHECK_HOST_API}/check-result/${rid}`, {
        headers: { accept: "application/json" },
        signal: withTimeout(15000),
      });
    } catch (e) {
      continue;
    }
    if (!rres.ok) continue;
    let rd;
    try {
      rd = await rres.json();
    } catch (e) {
      continue;
    }
    if (!rd || typeof rd !== "object") continue;
    const collected = {};
    let pending = false;
    for (const n of nodes) {
      const raw = rd[n.id];
      if (raw === null || raw === undefined) {
        pending = true;
        continue;
      }
      const atts = pingAttempts(raw);
      if (!atts.length) {
        pending = true;
        continue;
      }
      let ok = 0;
      for (const a of atts) if (a[0] === "OK") ok++;
      collected[n.id] = { city: n.city, ok, total: atts.length };
    }
    if (Object.keys(collected).length) out = collected;
    if (!pending && Object.keys(collected).length === nodes.length) return { nodes: collected };
  }
  if (out) return { nodes: out };
  return { error: "no_result" };
}

async function globalpingPing(target, cfg) {
  const limit = Math.max(1, Math.min(50, (cfg && cfg.probes) || 50));
  const headers = { "content-type": "application/json", "user-agent": "dns-telegram-bot" };
  if (cfg && cfg.gpToken) headers.Authorization = `Bearer ${cfg.gpToken}`;
  let res;
  try {
    res = await fetch("https://api.globalping.io/v1/measurements", {
      method: "POST",
      headers,
      body: JSON.stringify({ type: "ping", target, locations: [{ country: "IR" }], limit, measurementOptions: { packets: 4 } }),
      signal: withTimeout(20000),
    });
  } catch (e) {
    return { error: "gp_fetch" };
  }
  if (!res.ok) return { error: `gp_http_${res.status}` };
  let data;
  try {
    data = await res.json();
  } catch (e) {
    return { error: "gp_json" };
  }
  const id = data && data.id;
  if (!id) return { error: "gp_api" };
  for (let attempt = 0; attempt < 6; attempt++) {
    await sleep(attempt === 0 ? 2500 : 2000);
    let rr;
    try {
      rr = await fetch(`https://api.globalping.io/v1/measurements/${id}`, {
        headers: cfg && cfg.gpToken ? { "user-agent": "dns-telegram-bot", Authorization: `Bearer ${cfg.gpToken}` } : { "user-agent": "dns-telegram-bot" },
        signal: withTimeout(15000),
      });
    } catch (e) {
      continue;
    }
    if (!rr.ok) continue;
    let jj;
    try {
      jj = await rr.json();
    } catch (e) {
      continue;
    }
    if (!jj || jj.status !== "finished") continue;
    const nodes = {};
    let idx = 0;
    for (const r of jj.results || []) {
      const p = r.probe || {};
      const res = r.result || {};
      const st = res.stats || {};
      const total = Number(st.total) || 0;
      const rcv = Number(st.rcv) || 0;
      const failed = res.status !== "finished" || total === 0;
      nodes[`${p.country || "IR"}|${p.city || "IR"}|${p.asn || "?"}|${idx++}`] = {
        city: p.city || p.country || "IR",
        network: p.network || "?",
        asn: p.asn || "?",
        ok: failed ? 0 : rcv,
        total: total || 1,
        failed,
      };
    }
    if (!Object.keys(nodes).length) return { error: "gp_no_result" };
    return { nodes };
  }
  return { error: "gp_timeout" };
}

async function pingTarget(target, cfg, env) {
  if (cfg.provider === "checkhost") return checkHostPing(target, cfg.citiesSel, env);
  return globalpingPing(target, cfg);
}

function hostFilterPingBlocked(ping, cfg) {
  if (!ping || ping.error || !ping.nodes) return null;
  const isCheckHost = cfg && cfg.provider === "checkhost";
  const sel = cfg && Array.isArray(cfg.citiesSel) && cfg.citiesSel.length ? cfg.citiesSel : IR_CITIES;
  const maxOk = cfg && Number.isInteger(cfg.maxOk) ? cfg.maxOk : 0;
  const byCity = {};
  let blockedProbes = 0;
  let totalProbes = 0;
  for (const nid of Object.keys(ping.nodes)) {
    const n = ping.nodes[nid];
    if (isCheckHost && !sel.includes(n.city)) continue;
    totalProbes++;
    const bad = n.ok <= maxOk;
    if (bad) blockedProbes++;
    if (!byCity[n.city]) byCity[n.city] = { nodes: 0, blocked: 0 };
    byCity[n.city].nodes++;
    if (bad) byCity[n.city].blocked++;
  }
  let blockedCities = 0;
  for (const c of Object.keys(byCity)) {
    if (byCity[c].nodes > 0 && byCity[c].blocked === byCity[c].nodes) blockedCities++;
  }
  return { blockedCities, blockedProbes, totalProbes, byCity };
}

function hostFilterIsBlocked(info, cfg) {
  if (!info) return false;
  if (cfg.provider === "checkhost") return info.blockedCities >= cfg.cities;
  return info.blockedProbes >= cfg.minFail;
}

function zoneForName(zones, name) {
  const lower = String(name || "").toLowerCase();
  let best = null;
  for (const z of zones || []) {
    const zn = String(z.name || "").toLowerCase();
    if (!zn) continue;
    if (lower === zn || lower.endsWith("." + zn)) {
      if (!best || zn.length > best.name.length) best = z;
    }
  }
  return best;
}

async function hostFilterNewName(zones, accounts, kv, oldName) {
  const lower = String(oldName).toLowerCase();
  let zone = zoneForName(zones, lower);
  let fallback = false;
  let rel;
  if (zone) {
    const zn = zone.name.toLowerCase();
    rel = lower === zn ? zn.split(".")[0] : lower.slice(0, -(zn.length + 1));
    rel =
      rel
        .split(".")
        .map((p) => p.replace(/[^a-z0-9-]/g, ""))
        .filter(Boolean)
        .join(".") || zn.split(".")[0];
  } else {
    for (const root of HOSTFILTER_FALLBACK_ROOTS) {
      const z = zoneForName(zones, root);
      if (z) {
        zone = z;
        break;
      }
    }
    if (!zone) {
      const sorted = [...(zones || [])].sort((a, b) => a.name.length - b.name.length);
      zone = sorted[0] || null;
    }
    if (!zone) return { error: "no_zone" };
    fallback = true;
    rel = lower.split(".")[0].replace(/[^a-z0-9-]/g, "") || "cdn";
  }
  const records = await getRecords(zone, accounts, kv);
  const names = new Set(records.map((r) => String(r.name).toLowerCase()));
  let newName = "";
  for (let n = 1; n <= 60; n++) {
    const cand = `${rel}${n}.${zone.name}`.toLowerCase();
    if (!names.has(cand)) {
      newName = cand;
      break;
    }
  }
  if (!newName) return { error: "no_free_name" };
  let source = null;
  if (!fallback) {
    source = records.filter((r) => String(r.name).toLowerCase() === lower && ["A", "AAAA", "CNAME"].includes(r.type));
  }
  return { zone, name: newName, source, fallback };
}

async function cfCreateRecords(zone, name, source, accounts, kv, oldName) {
  const payloads = [];
  if (source && source.length) {
    for (const r of source) payloads.push({ type: r.type, name, content: r.content, proxied: !!r.proxied, ttl: r.ttl || 1 });
  } else {
    payloads.push({ type: "CNAME", name, content: oldName, proxied: false, ttl: 1 });
  }
  const created = [];
  for (const p of payloads) {
    const res = await fetch(`${CF_API}/zones/${zone.id}/dns_records`, {
      method: "POST",
      headers: hdr(accounts[zone._acc].token),
      body: JSON.stringify(p),
      signal: withTimeout(15000),
    });
    const data = await res.json();
    if (!data.success) return { error: cfErrText(data) };
    created.push(data.result);
  }
  await invalidateCache(kv, zone.id);
  return { records: created };
}

async function panelHosts(p, token, timeoutMs) {
  const base = p.url.replace(/\/+$/, "");
  const res = await fetch(`${base}/api/hosts`, {
    headers: { Authorization: `Bearer ${token}` },
    signal: withTimeout(timeoutMs || 25000),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  return Array.isArray(data) ? data : [];
}

async function panelPutHost(p, token, host) {
  const base = p.url.replace(/\/+$/, "");
  const body = { ...host };
  delete body.id;
  const res = await fetch(`${base}/api/host/${host.id}`, {
    method: "PUT",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: withTimeout(30000),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail = data && data.detail ? JSON.stringify(data.detail).substring(0, 300) : `HTTP ${res.status}`;
    return { error: detail };
  }
  return { host: data };
}

async function hfNotify(botToken, admins, text, kb) {
  for (const a of admins) {
    try {
      await sendMessage(botToken, a, text, kb);
    } catch (e) {
      console.error("HF_NOTIFY", String(e));
    }
  }
}

async function hostFilterRevert(kv, env, panelId, hostId) {
  const panels = await getPanels(kv);
  const panel = panels.find((p) => p.id === panelId);
  if (!panel) return { error: "panel_not_found" };
  const states = await getHostStateAll(kv);
  const key = `${panelId}:${hostId}`;
  const st = states[key];
  if (!st || !st.original) return { error: "no_state" };
  const token = await panelLogin(panel);
  if (!token) return { error: "login_failed" };
  let hosts;
  try {
    hosts = await panelHosts(panel, token);
  } catch (e) {
    return { error: "fetch_failed" };
  }
  const host = hosts.find((h) => String(h.id) === String(hostId));
  if (!host) return { error: "host_not_found" };
  for (const f of ["address", "sni", "host"]) {
    if (Array.isArray(st.original[f])) host[f] = st.original[f];
  }
  const put = await panelPutHost(panel, token, host);
  if (put.error) return { error: put.error };
  delete states[key];
  await saveHostStateAll(kv, states);
  await hostFilterLog(kv, { ts: new Date().toISOString(), kind: "revert", panel_id: panelId, host_id: Number(hostId), remark: host.remark });
  return { ok: true };
}

function hfIsReality(host) {
  const hay = [host && host.inbound_tag, host && host.remark, host && host.security]
    .map((x) => String(x || ""))
    .join(" ");
  return /reality/i.test(hay);
}

function hfIsFastly(host, value) {
  const hay = [value, host && host.inbound_tag, host && host.remark, host && host.address, host && host.sni, host && host.host]
    .map((x) => (Array.isArray(x) ? x.join(" ") : String(x || "")))
    .join(" ");
  return /fastly/i.test(hay);
}

async function getHfBackups(kv) {
  const b = await kv.get("host_filter_backups", "json");
  return Array.isArray(b) ? b : [];
}

async function saveHfBackups(kv, list) {
  await kv.put("host_filter_backups", JSON.stringify(list));
}

async function hfSnapshot(kv, env, label) {
  const cfg = await getHostFilterCfg(kv);
  const panels = await getPanels(kv);
  const hosts = [];
  for (const panel of panels) {
    const token = await panelLogin(panel);
    if (!token) continue;
    let list;
    try {
      list = await panelHosts(panel, token);
    } catch (e) {
      continue;
    }
    for (const h of list) {
      hosts.push({ panel_id: panel.id, host_id: h.id, remark: h.remark, address: h.address || [], sni: h.sni || [], host: h.host || [] });
    }
  }
  const backups = await getHfBackups(kv);
  const entry = { id: makeToken() + makeToken(), ts: new Date().toISOString(), label: label || "دستی", count: hosts.length, hosts };
  backups.unshift(entry);
  while (backups.length > cfg.backupKeep) backups.pop();
  await saveHfBackups(kv, backups);
  return entry;
}

async function hfStoreSnapshotFrom(kv, cfg, label, hostItems) {
  const hosts = [];
  for (const it of hostItems) {
    hosts.push({ panel_id: it.panel.id, host_id: it.host.id, remark: it.host.remark, address: it.orig.address || [], sni: it.orig.sni || [], host: it.orig.host || [] });
  }
  const backups = await getHfBackups(kv);
  const entry = { id: makeToken() + makeToken(), ts: new Date().toISOString(), label: label || "خودکار", count: hosts.length, hosts };
  backups.unshift(entry);
  while (backups.length > cfg.backupKeep) backups.pop();
  await saveHfBackups(kv, backups);
  return entry;
}

async function hfRestoreBackup(kv, env, id) {
  const backups = await getHfBackups(kv);
  const b = backups.find((x) => x.id === id);
  if (!b) return { error: "backup_not_found" };
  const panels = await getPanels(kv);
  const byPanel = {};
  for (const h of b.hosts || []) (byPanel[h.panel_id] = byPanel[h.panel_id] || []).push(h);
  let ok = 0;
  let fail = 0;
  for (const pid of Object.keys(byPanel)) {
    const panel = panels.find((p) => p.id === pid);
    if (!panel) {
      fail += byPanel[pid].length;
      continue;
    }
    const token = await panelLogin(panel);
    if (!token) {
      fail += byPanel[pid].length;
      continue;
    }
    let list;
    try {
      list = await panelHosts(panel, token);
    } catch (e) {
      fail += byPanel[pid].length;
      continue;
    }
    for (const snap of byPanel[pid]) {
      const host = list.find((x) => String(x.id) === String(snap.host_id));
      if (!host) {
        fail++;
        continue;
      }
      for (const f of ["address", "sni", "host"]) if (Array.isArray(snap[f])) host[f] = snap[f];
      const put = await panelPutHost(panel, token, host);
      if (put.error) fail++;
      else ok++;
    }
  }
  await hostFilterLog(kv, { ts: new Date().toISOString(), kind: "restore", backup_id: id, label: b.label, ok, fail });
  return { ok, fail };
}

async function runReminders(env) {
  const kv = env.BOT_KV;
  if (!kv) return;
  const botToken = env.BOT_TOKEN || BOT_TOKEN;
  const list = await getReminders(kv);
  const now = Date.now();
  const due = list.filter((r) => r && !r.notifiedAt && Number(r.at) <= now);
  if (!due.length) return;
  // علامت‌گذاری به‌عنوان اطلاع‌داده‌شده (برای دکمهٔ «یادآوری مجدد» نگه می‌داریم)
  for (const r of due) r.notifiedAt = now;
  await saveReminders(kv, list);
  const admins = await getAdmins(kv, env);
  for (const r of due) {
    const targets = new Set([...admins, r.by]);
    let msg = r.kind === "expiry" ? "⏰ یادآور انقضای سرور\n\n" : "⏰ یادآور\n\n";
    if (r.target && r.target.label) msg += `🎯 ${remPlain(r.target.label)}\n`;
    if (r.text) msg += `📝 ${remPlain(r.text)}\n`;
    if (r.kind === "expiry" && r.expiryAt) {
      msg += `🗓 انقضا: ${fmtJalali(r.expiryAt)}\n`;
      msg += `⏳ برای تمدید از سایت مربوطه اقدام کن.`;
    } else {
      msg += `🕒 ${fmtJalali(r.at)}`;
    }
    const kb = [
      [{ text: "🔁 یادآوری مجدد", callback_data: `remagain:${r.id}` }],
      [{ text: "👀 دیدم", callback_data: `remack:${r.id}` }],
    ];
    for (const t of targets) {
      try {
        await sendMessage(botToken, t, msg, kb);
      } catch (e) {}
    }
  }
}

async function runHostFilter(env, opts = {}) {
  const kv = env.BOT_KV;
  if (!kv) return { error: "no_kv" };
  const botToken = env.BOT_TOKEN || BOT_TOKEN;
  const cfg = await getHostFilterCfg(kv);
  cfg.gpToken = (env && env.GLOBALPING_TOKEN) || cfg.gpToken || "";
  const mr = cfg.manual_request;
  const manual = !!(mr && (!cfg.last_run || Date.parse(mr.ts) >= Date.parse(cfg.last_run)));
  const manualBy = manual ? mr.by : null;
  if (manual) {
    cfg.manual_request = null;
    cfg.last_attempt = new Date().toISOString();
    await saveHostFilterCfg(kv, cfg);
  }
  const report = async (msg) => {
    if (manualBy) {
      try {
        await sendMessage(botToken, manualBy, msg);
      } catch (e) {}
    }
  };
  if (!cfg.enabled && !opts.force && !manual) return { skipped: "disabled", cfg };

  if (!opts.force && !manual) {
    const lastMs = cfg.last_attempt ? Date.parse(cfg.last_attempt) : 0;
    if (lastMs && Date.now() - lastMs < cfg.intervalMin * 60000) return { skipped: "interval", cfg };
  }
  if (!manual) {
    cfg.last_attempt = new Date().toISOString();
    await saveHostFilterCfg(kv, cfg);
  }

  const accounts = await getAccounts(kv, env);
  const panels = await getPanels(kv);
  if (!accounts.length || !panels.length) {
    cfg.last_run = new Date().toISOString();
    cfg.last_summary = "اکانت کلادفلر یا پنل ثبت نشده.";
    await saveHostFilterCfg(kv, cfg);
    await report("❌ بررسی انجام نشد: اکانت کلادفلر یا پنل ثبت نشده.");
    return { error: "not_ready", cfg };
  }
  const zones = await getAllZones(accounts, kv);

  // Control probe: if the checker itself is down, do nothing.
  if (cfg.provider === "checkhost") {
    const control = await checkHostPing("www.google.com", IR_CITIES, env);
    if (control.error) {
      const wasDown = !!cfg.checkhost_down;
      cfg.checkhost_down = { ts: new Date().toISOString(), reason: control.error };
      cfg.last_run = new Date().toISOString();
      cfg.last_summary = "check-host در دسترس نبود؛ هیچ تغییری انجام نشد.";
      await saveHostFilterCfg(kv, cfg);
      if (!wasDown && !opts.manual) {
        const admins = await getAdmins(kv, env);
        await hfNotify(botToken, admins, "⚠️ تعویض خودکار هاست: سایت check-host فعلاً در دسترس نیست. تا برگشتن آن هیچ دامنه‌ای تعویض نمی‌شود.");
      }
      await report("⚠️ بررسی انجام نشد: سرویس check-host در دسترس نیست.");
      return { checkhost_down: true, cfg };
    }
  }
  cfg.checkhost_down = null;

  // Gather enabled hosts and their domain values.
  const hostItems = [];
  const uniqSet = new Set();
  const hostList = [];
  const hostSeen = new Set();
  for (const panel of panels) {
    const token = await panelLogin(panel);
    if (!token) continue;
    let hosts;
    try {
      hosts = await panelHosts(panel, token);
    } catch (e) {
      console.error("HF_HOSTS", e && e.message ? e.message : String(e));
      continue;
    }
    for (const h of hosts) {
      if (h.is_disabled) continue;
      // لیست سرورها برای یادآور (کش)
      {
        const addrs = Array.isArray(h.address) ? h.address : [];
        const ip = addrs.find((v) => /^\d{1,3}(\.\d{1,3}){3}$/.test(String(v))) || addrs[0] || "";
        const rec = {
          panel_id: panel.id,
          panel_name: panel.name,
          host_id: h.id,
          remark: String(h.remark || "").trim(),
          ip: String(ip || "").trim(),
        };
        const key = rec.ip ? "ip:" + rec.ip : "rm:" + rec.remark;
        if (!hostSeen.has(key)) {
          hostSeen.add(key);
          hostList.push(rec);
        }
      }
      if ((cfg.exceptions || []).includes(panel.id + ":" + h.id)) continue;
      const domains = new Set();
      for (const f of ["address", "sni", "host"]) {
        const arr = Array.isArray(h[f]) ? h[f] : [];
        for (const v of arr) {
          if (isDomainLike(v)) {
            const lv = String(v).toLowerCase();
            domains.add(lv);
            uniqSet.add(lv);
          }
        }
      }
      if (!domains.size) continue;
      hostItems.push({
        panel,
        token,
        host: h,
        domains: [...domains],
        orig: { address: h.address || [], sni: h.sni || [], host: h.host || [] },
      });
    }
  }
  if (hostList.length) await kvPutCached(kv, "hosts_cache", JSON.stringify(hostList), { expirationTtl: 3600 }, 3600000);
  const uniq = [...uniqSet];
  if (!uniq.length) {
    cfg.last_run = new Date().toISOString();
    cfg.last_summary = "دامنه‌ای برای بررسی پیدا نشد.";
    await saveHostFilterCfg(kv, cfg);
    await report("📭 بررسی انجام نشد: دامنه‌ای در هاست‌های فعال پیدا نشد.");
    return { checked: 0, changed: 0, cfg };
  }

  // Rotating batch (bounded by worker subrequests / API rate limits; over cycles all domains get checked).
  const effBatch = cfg.gpToken ? 60 : cfg.batch;
  const batch = Math.max(1, Math.min(60, opts.batchOverride || effBatch));
  const start = cfg.cursor % uniq.length;
  const take = manual ? uniq.length : Math.min(batch, uniq.length);
  const slice = [];
  for (let i = 0; i < take; i++) slice.push(uniq[(start + i) % uniq.length]);
  cfg.cursor = (start + take) % uniq.length;

  // Ping checks.
  const results = {};
  let anyCheck = false;
  for (const t of slice) {
    const ping = await pingTarget(t, cfg, env);
    if (ping.error) {
      await sleep(700);
      continue;
    }
    results[t] = ping;
    anyCheck = true;
    await sleep(1000);
  }
  if (!anyCheck) {
    cfg.checkhost_down = { ts: new Date().toISOString(), reason: "no_results" };
    cfg.last_run = new Date().toISOString();
    cfg.last_summary = "سرویس بررسی نتیجه نداد؛ هیچ تغییری انجام نشد.";
    await saveHostFilterCfg(kv, cfg);
    await report("⚠️ بررسی انجام نشد: سرویس بررسی (Globalping/check-host) نتیجه نداد.");
    return { checkhost_down: true, cfg };
  }

  // First pass filter.
  let filtered = {};
  for (const t of Object.keys(results)) {
    const info = hostFilterPingBlocked(results[t], cfg);
    if (!hostFilterIsBlocked(info, cfg)) continue;
    const ips = await resolveIPs(t, kv);
    if (!ips || !ips.length) continue; // dead / non-resolving domain, not a filter
    filtered[t] = info;
  }

  // Confirmation: re-check after one minute.
  if (Object.keys(filtered).length && !opts.skipRecheck) {
    await sleep(60000);
    const still = {};
    for (const t of Object.keys(filtered)) {
      const ping2 = await pingTarget(t, cfg, env);
      if (!ping2.error) {
        const info2 = hostFilterPingBlocked(ping2, cfg);
        if (hostFilterIsBlocked(info2, cfg)) still[t] = info2;
      }
      await sleep(1000);
    }
    filtered = still;
  }

  if (opts.dryRun) {
    cfg.last_run = new Date().toISOString();
    cfg.last_summary = `بررسی دستی ${slice.length} دامنه — ${Object.keys(filtered).length} فیلتر (بدون تغییر).`;
    await saveHostFilterCfg(kv, cfg);
    return { checked: slice.length, filtered: Object.keys(filtered).length, changed: 0, ipBlocked: 0, dryRun: true, cfg };
  }

  const states = await getHostStateAll(kv);
  const admins = await getAdmins(kv, env);
  const ipCache = {};
  const maxChanges = Math.max(1, Number(opts.maxChanges) || cfg.maxChanges);
  let changedCount = 0;
  let ipBlockedCount = 0;
  let didBackup = false;

  for (const item of hostItems) {
    if (changedCount >= maxChanges) break;
    const repl = {};
    const events = [];
    for (const field of ["address", "sni", "host"]) {
      const arr = Array.isArray(item.host[field]) ? item.host[field] : [];
      for (const v of arr) {
        const dv = String(v).toLowerCase();
        if (!filtered[dv] || repl[dv]) continue;

        // REALITY / Fastly configs: alert only, never change.
        if (hfIsReality(item.host) || hfIsFastly(item.host, dv)) {
          const why = hfIsReality(item.host) ? "REALITY" : "Fastly";
          await hostFilterLog(kv, { ts: new Date().toISOString(), kind: "protected", panel_id: item.panel.id, host_id: item.host.id, from: dv, reason: why });
          await hfNotify(
            botToken,
            admins,
            "🔒 دامنه فیلتر شد ولی کانفیگ " + why + " است؛ فقط هشدار (بدون تغییر):\n" +
              "🖥 پنل: " + escHtml(item.panel.name) + "\n📄 هاست: " + escHtml(String(item.host.remark || item.host.id).substring(0, 60)) + "\n🔗 " + code(dv)
          );
          continue;
        }

        // Diagnose IP block vs domain block.
        let diag = ipCache[dv];
        if (!diag) {
          diag = { ipBlocked: false, ip: null };
          const ips = await resolveIPs(dv, kv);
          if (ips && ips[0]) {
            diag.ip = ips[0];
            const ipp = await pingTarget(ips[0], cfg, env);
            if (!ipp.error) {
              const ii = hostFilterPingBlocked(ipp, cfg);
              if (hostFilterIsBlocked(ii, cfg)) diag.ipBlocked = true;
            }
            await sleep(900);
          }
          ipCache[dv] = diag;
        }
        if (diag.ipBlocked) {
          ipBlockedCount++;
          const txt =
            "🚫 آی‌پی فیلتر است (نه دامنه)\n" +
            "🖥 پنل: " + escHtml(item.panel.name) + "\n" +
            "📄 هاست: " + escHtml(String(item.host.remark || item.host.id).substring(0, 60)) + "\n" +
            "🔗 دامنه: " + code(dv) + "\n" +
            "🌐 آی‌پی: " + code(diag.ip || "?") + "\n" +
            "⏱ " + ndFmtTs(new Date().toISOString()) + " به وقت ایران";
          await hfNotify(botToken, admins, txt);
          await hostFilterLog(kv, { ts: new Date().toISOString(), kind: "ip_blocked", panel_id: item.panel.id, host_id: item.host.id, from: dv, ip: diag.ip });
          continue;
        }

        // For sni/host camouflage values only rotate our own zones; alert otherwise.
        if (field !== "address" && !zoneForName(zones, dv)) {
          await hostFilterLog(kv, { ts: new Date().toISOString(), kind: "external_sni", panel_id: item.panel.id, host_id: item.host.id, from: dv });
          await hfNotify(
            botToken,
            admins,
            "⚠️ مقدار " + code(field) + " فیلتر تشخیص داده شد ولی دامنه‌اش در اکانت‌های کلادفلر ما نیست:\n" +
              "🖥 پنل: " + escHtml(item.panel.name) + "\n📄 هاست: " + escHtml(String(item.host.remark || item.host.id).substring(0, 60)) + "\n🔗 " + code(dv)
          );
          continue;
        }

        if (!didBackup) {
          await hfStoreSnapshotFrom(kv, cfg, "خودکار قبل از تعویض", hostItems);
          didBackup = true;
        }
        const nn = await hostFilterNewName(zones, accounts, kv, dv);
        if (nn.error) {
          await hostFilterLog(kv, { ts: new Date().toISOString(), kind: "new_name_fail", from: dv, error: nn.error });
          continue;
        }
        const cr = await cfCreateRecords(nn.zone, nn.name, nn.source, accounts, kv, dv);
        if (cr.error) {
          await hostFilterLog(kv, { ts: new Date().toISOString(), kind: "create_fail", from: dv, to: nn.name, error: cr.error });
          continue;
        }
        repl[dv] = nn.name;
        events.push({ field, from: dv, to: nn.name, zone: nn.zone.name });
      }
    }
    if (!events.length) continue;

    for (const field of ["address", "sni", "host"]) {
      if (Array.isArray(item.host[field])) item.host[field] = item.host[field].map((v) => repl[String(v).toLowerCase()] || v);
    }
    const put = await panelPutHost(item.panel, item.token, item.host);
    if (put.error) {
      for (const ev of events) {
        await hostFilterLog(kv, { ts: new Date().toISOString(), kind: "put_fail", host_id: item.host.id, from: ev.from, to: ev.to, error: put.error });
      }
      continue;
    }

    changedCount++;
    const key = item.panel.id + ":" + item.host.id;
    const prev = states[key];
    states[key] = {
      panel_id: item.panel.id,
      host_id: item.host.id,
      remark: item.host.remark,
      original: prev ? prev.original : item.orig,
      current: { address: item.host.address || [], sni: item.host.sni || [], host: item.host.host || [] },
      changed_at: new Date().toISOString(),
    };

    const lines = [
      "🔄 دامنهٔ هاست تعویض شد",
      "🖥 پنل: " + escHtml(item.panel.name),
      "📄 هاست: " + escHtml(String(item.host.remark || item.host.id).substring(0, 60)),
    ];
    for (const ev of events) lines.push("• " + ev.field + ": " + code(ev.from) + " ➜ " + code(ev.to) + " (" + escHtml(ev.zone) + ")");
    lines.push("⏱ " + ndFmtTs(new Date().toISOString()) + " به وقت ایران");
    const kb = [[{ text: "↩️ دامنهٔ قبلی را جایگزین کن", callback_data: "hfrev:" + key }]];
    await hfNotify(botToken, admins, lines.join("\n"), kb);
    await hostFilterLog(kv, { ts: new Date().toISOString(), kind: "rotated", panel_id: item.panel.id, host_id: item.host.id, remark: item.host.remark, events });
  }

  await saveHostStateAll(kv, states);
  cfg.last_run = new Date().toISOString();
  cfg.last_summary = `بررسی ${slice.length} دامنه — ${changedCount} تعویض، ${ipBlockedCount} آی‌پی فیلتر.`;
  await saveHostFilterCfg(kv, cfg);
  await report(
    "✅ بررسی کامل انجام شد.\n" +
      `🔎 بررسی‌شده: ${slice.length}\n` +
      `🔴 فیلتر تأییدشده: ${Object.keys(filtered).length}\n` +
      `🔄 تعویض: ${changedCount}\n` +
      `🚫 آی‌پی فیلتر: ${ipBlockedCount}`
  );
  return { checked: slice.length, filtered: Object.keys(filtered).length, changed: changedCount, ipBlocked: ipBlockedCount, cfg };
}

async function renderHostFilterHome(edit, kv, env) {
  const cfg = await getHostFilterCfg(kv);
  const states = await getHostStateAll(kv);
  const backups = await getHfBackups(kv);
  const count = Object.keys(states).length;
  const lines = ["🧭 تعویض خودکار هاست فیلتر", ""];
  lines.push("وضعیت: " + (cfg.enabled ? "▶️ فعال" : "⏸ غیرفعال"));
  lines.push("🔌 سرویس بررسی: " + (cfg.provider === "checkhost" ? "check-host" : "Globalping (پیش‌فرض)"));
  lines.push("⏱ فاصلهٔ اجرا: هر " + cfg.intervalMin + " دقیقه");
  if (cfg.provider === "checkhost") {
    lines.push("🌆 شهرها: " + cfg.citiesSel.join("، "));
    lines.push("🎯 آستانه: " + cfg.cities + " شهر از " + cfg.citiesSel.length + " (پینگ موفق ≤ " + cfg.maxOk + " از ۴)");
  } else {
    lines.push("🎯 آستانه: " + cfg.minFail + " پروب ایرانی از " + cfg.probes + " (پینگ موفق ≤ " + cfg.maxOk + " از ۴)");
  }
  lines.push("📦 تعداد هر اجرا: " + cfg.batch + " · 🔁 حداکثر تعویض: " + cfg.maxChanges);
  lines.push("💾 بکاپ‌های نگه‌داشته: " + backups.length + " (حداکثر " + cfg.backupKeep + ")");
  if (cfg.last_run) lines.push("🕐 آخرین اجرا: " + ndFmtTs(cfg.last_run) + " به وقت ایران");
  if (cfg.last_summary) lines.push("📝 " + escHtml(cfg.last_summary));
  if (cfg.checkhost_down) lines.push("⚠️ سرویس بررسی در دسترس نیست (از " + ndFmtTs(cfg.checkhost_down.ts) + ")");
  lines.push("🔁 هاست‌های تعویض‌شده: " + count);
  lines.push("");
  lines.push("روش: دامنه‌های هاست‌ها هر " + cfg.intervalMin + " دقیقه از داخل ایران بررسی می‌شوند؛ در صورت فیلتر، یک دامنهٔ شماره‌دار جدید ساخته و در همان هاست جایگزین می‌شود. کانفیگ‌های REALITY/Fastly فقط هشدار می‌گیرند.");
  const kb = [];
  kb.push([{ text: cfg.enabled ? "⏸ غیرفعال‌سازی" : "▶️ فعال‌سازی", callback_data: "hftg" }]);
  kb.push([{ text: "🔎 بررسی فوری", callback_data: "hfcheck" }, { text: "📜 تاریخچه", callback_data: "hfhist" }]);
  kb.push([{ text: "📋 لیست هاست‌ها", callback_data: "hflist" }]);
  kb.push([{ text: "🔌 سرویس: " + (cfg.provider === "checkhost" ? "check-host" : "Globalping"), callback_data: "hfsetprov" }]);
  kb.push([{ text: "⚙️ تنظیمات", callback_data: "hfset" }, { text: "💾 بکاپ", callback_data: "hfbk" }]);
  kb.push([{ text: "🔙 بازگشت", callback_data: "nd" }]);
  await edit(lines.join("\n"), kb);
}

async function renderHostFilterSettings(edit, kv) {
  const cfg = await getHostFilterCfg(kv);
  const lines = ["⚙️ تنظیمات تعویض خودکار هاست", ""];
  lines.push("مقادیر قابل تغییر (با زدن روی هر مورد، عدد/گزینهٔ تازه را بفرست):");
  lines.push("• 🔌 سرویس بررسی: " + (cfg.provider === "checkhost" ? "check-host (نیاز به رله)" : "Globalping"));
  lines.push("• ⏱ فاصلهٔ اجرا: " + cfg.intervalMin + " دقیقه");
  if (cfg.provider === "checkhost") {
    lines.push("• 🌆 شهرهای بررسی‌شده: " + cfg.citiesSel.join("، "));
    lines.push("• 🎯 حداقل شهرهای فیلتر: " + cfg.cities);
  } else {
    lines.push("• 📡 تعداد پروب ایرانی: " + cfg.probes);
    lines.push("• 🎯 حداقل پروب فیلتر: " + cfg.minFail);
  }
  lines.push("• 📶 حداکثر پینگ موفق مجاز: " + cfg.maxOk + " از ۴");
  lines.push("• 📦 تعداد بررسی در هر اجرا: " + cfg.batch);
  lines.push("• 🔁 حداکثر تعویض در هر اجرا: " + cfg.maxChanges);
  lines.push("• 💾 تعداد بکاپ‌های نگه‌داشته: " + cfg.backupKeep);
  if (cfg.provider !== "checkhost") lines.push("• 🔑 توکن Globalping: " + (cfg.gpToken ? "ثبت شده ✅" : "ثبت نشده"));
  const kb = [];
  kb.push([{ text: "🔌 تغییر سرویس", callback_data: "hfsetprov" }]);
  kb.push([{ text: "⏱ فاصلهٔ اجرا", callback_data: "hfsetedit:interval" }]);
  if (cfg.provider === "checkhost") {
    kb.push([{ text: "🌆 انتخاب شهرها", callback_data: "hfcities" }]);
    kb.push([{ text: "🎯 حداقل شهر", callback_data: "hfsetedit:cities" }, { text: "📶 حداکثر پینگ موفق", callback_data: "hfsetedit:maxok" }]);
  } else {
    kb.push([{ text: "📡 تعداد پروب", callback_data: "hfsetedit:probes" }, { text: "🎯 حداقل پروب فیلتر", callback_data: "hfsetedit:minfail" }]);
    kb.push([{ text: "📶 حداکثر پینگ موفق", callback_data: "hfsetedit:maxok" }]);
  }
  kb.push([{ text: "📦 تعداد هر اجرا", callback_data: "hfsetedit:batch" }, { text: "🔁 حداکثر تعویض", callback_data: "hfsetedit:maxchanges" }]);
  if (cfg.provider !== "checkhost") kb.push([{ text: "🔑 توکن Globalping", callback_data: "hfsettoken" }]);
  kb.push([{ text: "💾 تعداد بکاپ", callback_data: "hfsetedit:backupkeep" }]);
  kb.push([{ text: "🔙 بازگشت", callback_data: "hf" }]);
  await edit(lines.join("\n"), kb);
}

async function renderHostFilterCities(edit, kv) {
  const cfg = await getHostFilterCfg(kv);
  const kb = IR_CITIES.map((c) => [{ text: (cfg.citiesSel.includes(c) ? "✅ " : "⬜ ") + c, callback_data: "hfcityt:" + c }]);
  kb.push([{ text: "🔙 بازگشت", callback_data: "hfset" }]);
  await edit("🌆 کدام شهرها بررسی شوند؟\n(حداقل یک شهر باید فعال بماند؛ حداقل شهرها خودکار اصلاح می‌شود)", kb);
}

async function renderHostFilterBackups(edit, kv) {
  const backups = await getHfBackups(kv);
  const lines = ["💾 بکاپ‌های هاست‌ها", ""];
  if (!backups.length) lines.push("📭 هنوز بکاپی گرفته نشده.");
  else for (const b of backups) lines.push("• " + ndFmtTs(b.ts) + " — " + escHtml(b.label || "-") + " (" + (b.count || 0) + " هاست)");
  const kb = [[{ text: "➕ گرفتن بکاپ جدید", callback_data: "hfbknow" }]];
  for (const b of backups) {
    kb.push([{ text: "↩️ " + ndFmtTs(b.ts), callback_data: "hfbkr:" + b.id }, { text: "🗑", callback_data: "hfbkdel:" + b.id }]);
  }
  kb.push([{ text: "🔙 بازگشت", callback_data: "hf" }]);
  await edit(lines.join("\n"), kb);
}

async function renderHostFilterHosts(edit, kv, env) {
  const panels = await getPanels(kv);
  const cfg = await getHostFilterCfg(kv);
  const exc = new Set(cfg.exceptions || []);
  const lines = ["📋 لیست هاست‌ها", "", "🔎 بررسی = چک فوری همین هاست · 🚫/✅ استثنا = حذف/افزودن از تعویض خودکار", ""];
  const kb = [];
  let n = 0;
  for (const panel of panels) {
    const token = await panelLogin(panel);
    if (!token) continue;
    let hosts;
    try {
      hosts = await panelHosts(panel, token);
    } catch (e) {
      continue;
    }
    for (const h of hosts) {
      n++;
      const addr = (Array.isArray(h.address) && h.address[0]) || "";
      const label = String(addr || h.remark || "host").substring(0, 24);
      const key = panel.id + ":" + h.id;
      const isExc = exc.has(key);
      lines.push(`${n}) ${h.is_disabled ? "⏸ " : ""}${label}`);
      kb.push([
        { text: "🔎 " + label.substring(0, 16), callback_data: `hfchk:${panel.id}:${h.id}` },
        { text: (isExc ? "✅" : "🚫") + " استثنا", callback_data: `hfexc:${panel.id}:${h.id}` },
      ]);
    }
  }
  if (!n) lines.push("📭 هاستی پیدا نشد.");
  kb.push([{ text: "🔙 بازگشت", callback_data: "hf" }]);
  await edit(lines.join("\n"), kb);
}

async function hfHostCheck(kv, env, panelId, hostId) {
  const back = [[{ text: "🔙 بازگشت به لیست", callback_data: "hflist" }]];
  const cfg = await getHostFilterCfg(kv);
  cfg.gpToken = (env && env.GLOBALPING_TOKEN) || cfg.gpToken || "";
  const panels = await getPanels(kv);
  const panel = panels.find((p) => p.id === panelId);
  if (!panel) return { text: "❌ پنل پیدا نشد.", kb: back };
  const token = await panelLogin(panel);
  if (!token) return { text: "❌ ورود به پنل ناموفق.", kb: back };
  let hosts;
  try {
    hosts = await panelHosts(panel, token);
  } catch (e) {
    return { text: "❌ خطا در خواندن هاست‌های پنل.", kb: back };
  }
  const h = hosts.find((x) => String(x.id) === String(hostId));
  if (!h) return { text: "❌ هاست پیدا نشد.", kb: back };
  if (h.is_disabled) {
    return { text: "⏸ این هاست غیرفعال است؛ بررسی نمی‌شود.", kb: back };
  }
  const excKey = String(panelId) + ":" + String(h.id);
  if ((cfg.exceptions || []).includes(excKey)) {
    return {
      text: "🚫 این هاست در لیست استثناست؛ بررسی نمی‌شود.\n\nاگر می‌خواهی بررسی شود، از لیست هاست دکمهٔ «✅ استثنا» را بزن تا از استثنا خارج شود.",
      kb: [[{ text: "✅ خروج از استثنا و بازگشت", callback_data: `hfexc:${panelId}:${h.id}` }]],
    };
  }
  const domains = new Set();
  for (const f of ["address", "sni", "host"]) {
    for (const v of h[f] || []) if (isDomainLike(v)) domains.add(String(v).toLowerCase());
  }
  const lines = [`🔎 بررسی هاست ${h.id}`, ""];
  if (!domains.size) lines.push("دامنه‌ای برای بررسی ندارد.");
  for (const d of domains) {
    const ping = await pingTarget(d, cfg, env);
    if (ping.error) {
      lines.push(`⚪ ${d} — خطای بررسی (${ping.error})`);
      continue;
    }
    const info = hostFilterPingBlocked(ping, cfg);
    const blocked = hostFilterIsBlocked(info, cfg);
    if (cfg.provider === "checkhost") lines.push(`${blocked ? "🔴" : "🟢"} ${d} — ${info.blockedCities}/${cfg.citiesSel.length} شهر بلاک`);
    else lines.push(`${blocked ? "🔴" : "🟢"} ${d} — ${info.blockedProbes}/${info.totalProbes} پروب بلاک`);
    for (const nid of Object.keys(ping.nodes)) {
      const n = ping.nodes[nid];
      const who = n.network ? `${n.network}${n.asn ? "/" + n.asn : ""}${n.city ? " - " + n.city : ""}` : `${nid}${n.city ? " - " + n.city : ""}`;
      lines.push(`   ${n.ok > 0 ? "🟢" : "🔴"} ${escHtml(who)}: ${n.ok}/${n.total}${n.failed ? " (failed/مسموم)" : ""}`);
    }
    await sleep(700);
  }
  return { text: lines.join("\n"), kb: back };
}
