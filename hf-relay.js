const http = require("http");
const { URL } = require("url");

const PORT = Number(process.env.HF_RELAY_PORT || 8787);
const TOKEN = process.env.HF_RELAY_TOKEN || "";
const API = "https://check-host.net";

const NODES = [
  { id: "ir1.node.check-host.net", city: "Tehran" },
  { id: "ir5.node.check-host.net", city: "Tehran" },
  { id: "ir7.node.check-host.net", city: "Tehran" },
  { id: "ir8.node.check-host.net", city: "Tehran" },
  { id: "ir2.node.check-host.net", city: "Isfahan" },
  { id: "ir3.node.check-host.net", city: "Shiraz" },
  { id: "ir4.node.check-host.net", city: "Shiraz" },
];

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
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

function json(res, code, obj) {
  const b = Buffer.from(JSON.stringify(obj));
  res.writeHead(code, { "content-type": "application/json", "content-length": b.length });
  res.end(b);
}

async function fetchJson(url, ms) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    const r = await fetch(url, {
      headers: { accept: "application/json", "user-agent": "Mozilla/5.0" },
      signal: ctrl.signal,
    });
    if (!r.ok) return { error: `http_${r.status}` };
    return { data: await r.json() };
  } catch (e) {
    return { error: "fetch" };
  } finally {
    clearTimeout(t);
  }
}

async function doPing(target, cities) {
  const nodes = NODES.filter((n) => cities.includes(n.city));
  if (!nodes.length) return { error: "no_city" };
  const qs = nodes.map((n) => `&node=${encodeURIComponent(n.id)}`).join("");
  const sub = await fetchJson(`${API}/check-ping?host=${encodeURIComponent(target)}${qs}`, 20000);
  if (sub.error) return { error: sub.error };
  const data = sub.data;
  if (!data || data.ok !== 1 || !data.request_id) return { error: "api" };
  const rid = data.request_id;
  let out = null;
  for (let attempt = 0; attempt < 5; attempt++) {
    await sleep(attempt === 0 ? 5000 : 3000);
    const rr = await fetchJson(`${API}/check-result/${rid}`, 15000);
    if (rr.error) continue;
    const rd = rr.data;
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

const server = http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    if (u.pathname !== "/check") return json(res, 404, { error: "not_found" });
    const token = u.searchParams.get("token") || "";
    if (!TOKEN || token !== TOKEN) return json(res, 403, { error: "forbidden" });
    const target = (u.searchParams.get("target") || "").trim().toLowerCase();
    if (!/^[a-z0-9._:-]+$/.test(target) || target.length > 253) return json(res, 400, { error: "bad_target" });
    let cities = (u.searchParams.get("cities") || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    cities = cities.filter((c) => NODES.some((n) => n.city === c));
    if (!cities.length) cities = [...new Set(NODES.map((n) => n.city))];
    const r = await doPing(target, cities);
    return json(res, 200, r);
  } catch (e) {
    return json(res, 500, { error: "internal" });
  }
});

server.listen(PORT, "0.0.0.0", () => console.log(`[hf-relay] listening on 0.0.0.0:${PORT}`));
