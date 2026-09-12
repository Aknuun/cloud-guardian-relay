// Host anti-filter relay for Deno Deploy (https://deno.com/deploy)
// Deploy: paste this file, set env HF_RELAY_TOKEN, then open
//   https://<your-project>.deno.dev/check?token=<TOKEN>&target=www.google.com
// It only talks to check-host.net (Cloudflare Workers are blocked by check-host).

const TOKEN = Deno.env.get("HF_RELAY_TOKEN") || "CHANGE_ME";
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

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function pingAttempts(raw: any): any[] {
  const out: any[] = [];
  const walk = (x: any) => {
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

async function fetchJson(url: string, ms: number): Promise<any> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    const r = await fetch(url, {
      headers: { accept: "application/json", "user-agent": "Mozilla/5.0" },
      signal: ctrl.signal,
    });
    if (!r.ok) return { error: `http_${r.status}` };
    return { data: await r.json() };
  } catch {
    return { error: "fetch" };
  } finally {
    clearTimeout(t);
  }
}

async function doPing(target: string, cities: string[]): Promise<any> {
  const nodes = NODES.filter((n) => cities.includes(n.city));
  if (!nodes.length) return { error: "no_city" };
  const qs = nodes.map((n) => `&node=${encodeURIComponent(n.id)}`).join("");
  const sub = await fetchJson(`${API}/check-ping?host=${encodeURIComponent(target)}${qs}`, 20000);
  if (sub.error) return { error: sub.error };
  const data = sub.data;
  if (!data || data.ok !== 1 || !data.request_id) return { error: "api" };
  const rid = data.request_id;
  let out: any = null;
  for (let attempt = 0; attempt < 5; attempt++) {
    await sleep(attempt === 0 ? 5000 : 3000);
    const rr = await fetchJson(`${API}/check-result/${rid}`, 15000);
    if (rr.error) continue;
    const rd = rr.data;
    if (!rd || typeof rd !== "object") continue;
    const collected: any = {};
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

Deno.serve(async (req: Request) => {
  try {
    const u = new URL(req.url);
    if (u.pathname !== "/check") return Response.json({ error: "not_found" }, { status: 404 });
    if (u.searchParams.get("token") !== TOKEN) return Response.json({ error: "forbidden" }, { status: 403 });
    const target = (u.searchParams.get("target") || "").trim().toLowerCase();
    if (!/^[a-z0-9._:-]+$/.test(target) || target.length > 253) {
      return Response.json({ error: "bad_target" }, { status: 400 });
    }
    let cities = (u.searchParams.get("cities") || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    cities = cities.filter((c) => NODES.some((n) => n.city === c));
    if (!cities.length) cities = [...new Set(NODES.map((n) => n.city))];
    return Response.json(await doPing(target, cities));
  } catch {
    return Response.json({ error: "internal" }, { status: 500 });
  }
});
