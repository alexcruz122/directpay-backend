// =============================================================================
// RedTrex Render Backend (api.redtrex.store) — HARDENED
// -----------------------------------------------------------------------------
// IMPORTANT: This file is for your RENDER service repo, NOT for this Replit
// project. The local /server.js in this Replit just serves static HTML pages.
//
// Security hardening applied:
//   - CORS allowlist (no wildcard)
//   - Body size limits
//   - Helmet-style security headers
//   - HTTPS redirect (trust proxy)
//   - Per-IP rate limiting on /login and /create-payment
//   - Login lockout after repeated failures
//   - Constant-time token comparison
//   - Random session IDs (cookie no longer holds the raw admin token)
//   - CSRF tokens on every admin POST form
//   - Server-generated order_id (cannot be supplied or overwritten by client)
//   - Amount/item bounds checking, prototype-pollution stripping
//   - No ?token= URL-string admin auth (was leaking via referer/logs)
// =============================================================================

import express from "express";
import crypto from "crypto";
import cors from "cors";

const app = express();
// Trust the immediate proxy hop only. We additionally derive the real client IP
// via clientIp() below (prefers Cloudflare's cf-connecting-ip, then the
// rightmost X-Forwarded-For entry — the leftmost is attacker-controllable).
app.set("trust proxy", 1);

function clientIp(req) {
  const cf = req.headers["cf-connecting-ip"];
  if (cf) return String(cf).trim();
  const xff = req.headers["x-forwarded-for"];
  if (xff) {
    const parts = String(xff).split(",").map(s => s.trim()).filter(Boolean);
    if (parts.length) return parts[parts.length - 1]; // rightmost = closest to us
  }
  return req.socket?.remoteAddress || req.ip || "unknown";
}

// ----- Body parsers with strict size limits -----
app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: true, limit: "20kb" }));

// ----- CORS allowlist -----
const ALLOWED_ORIGINS = new Set([
  "https://www.redtrex.com.lk",
  "https://redtrex.com.lk",
  "https://www.redtrex.store",
  "https://redtrex.store",
  "https://api.redtrex.store",
  "https://www.api.redtrex.store"
]);
app.use(cors({
  origin(origin, cb) {
    // No Origin header (server-to-server, curl, same-origin form POST in some
    // browsers): allow. Known origin: allow. Unknown: don't add CORS headers
    // (browser will block the response) but DON'T throw — throwing turns every
    // request into a 500 and breaks the admin pages themselves.
    if (!origin) return cb(null, true);
    if (ALLOWED_ORIGINS.has(origin)) return cb(null, true);
    console.warn("[cors] blocked origin:", origin);
    return cb(null, false);
  },
  credentials: true,
  methods: ["GET", "POST", "OPTIONS"]
}));

// ----- Security headers (Helmet-equivalent, no extra dep) -----
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("X-DNS-Prefetch-Control", "off");
  // Admin pages render their own inline CSS, so allow inline styles for self.
  res.setHeader("Content-Security-Policy",
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
  next();
});

// ----- Force HTTPS in production -----
app.use((req, res, next) => {
  const proto = req.headers["x-forwarded-proto"];
  if (proto && proto !== "https") {
    return res.redirect(301, `https://${req.headers.host}${req.url}`);
  }
  next();
});

const {
  DIRECTPAY_MERCHANT_ID,
  DIRECTPAY_SECRET,
  ADMIN_TOKEN,
  ORDERS_WORKER_URL = "https://redtrex-coupons.projectmmdoffcialdev.workers.dev",
  ORDERS_API_KEY,
  EMAIL_WORKER_URL = "https://resend.projectmmdoffcialdev.workers.dev",
  ORDER_EMAIL_TOKEN
} = process.env;

const COOKIE_NAME = "rt_admin";
const COOKIE_MAX_AGE_SEC = 60 * 60 * 24 * 7; // 7 days
const SERVICE_STATUSES = ["Pending", "Reviewing", "Scheduled", "In Progress", "Completed", "Cancelled"];
const SERVICE_TYPES = ["Software Installation", "Activation Help", "Data Recovery", "IT Support", "PC Repair", "Network Setup", "Custom"];

// Bounds for /create-payment
const MIN_AMOUNT_LKR = 10;
const MAX_AMOUNT_LKR = 500000;
const MAX_ITEMS = 20;
const MAX_ITEM_NAME = 200;

// =============================================================================
// In-memory session store (random session IDs; cookie no longer holds raw token)
// =============================================================================
const sessions = new Map(); // sid -> { ip, exp }

function createSession(ip) {
  const sid = crypto.randomBytes(32).toString("hex");
  const exp = Date.now() + COOKIE_MAX_AGE_SEC * 1000;
  sessions.set(sid, { ip, exp });
  return sid;
}
function isSessionValid(sid) {
  if (!sid) return false;
  const s = sessions.get(sid);
  if (!s) return false;
  if (s.exp < Date.now()) { sessions.delete(sid); return false; }
  return true;
}
function destroySession(sid) { if (sid) sessions.delete(sid); }

// Periodic cleanup
setInterval(() => {
  const now = Date.now();
  for (const [sid, s] of sessions) if (s.exp < now) sessions.delete(sid);
}, 60 * 60 * 1000);

// =============================================================================
// Rate limiter (sliding window per IP, in-memory)
// =============================================================================
function makeLimiter({ windowMs, max, key = req => clientIp(req) }) {
  const buckets = new Map(); // key -> [timestamps]
  return (req, res, next) => {
    const k = key(req);
    const now = Date.now();
    const arr = (buckets.get(k) || []).filter(t => now - t < windowMs);
    if (arr.length >= max) {
      res.setHeader("Retry-After", Math.ceil(windowMs / 1000));
      return res.status(429).send("Too many requests. Try again later.");
    }
    arr.push(now);
    buckets.set(k, arr);
    next();
  };
}
const loginLimiter   = makeLimiter({ windowMs: 15 * 60 * 1000, max: 8 });
const paymentLimiter = makeLimiter({ windowMs: 60 * 1000, max: 10 });
const generalLimiter = makeLimiter({ windowMs: 60 * 1000, max: 60 });

// =============================================================================
// Cookie + CSRF helpers
// =============================================================================
function parseCookies(header = "") {
  const out = {};
  header.split(";").forEach(p => {
    const i = p.indexOf("=");
    if (i > -1) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function setAdminCookie(res, sid) {
  res.setHeader("Set-Cookie",
    `${COOKIE_NAME}=${encodeURIComponent(sid)}; Max-Age=${COOKIE_MAX_AGE_SEC}; Path=/; HttpOnly; Secure; SameSite=Strict`);
}
function clearAdminCookie(res) {
  res.setHeader("Set-Cookie", `${COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict`);
}

// CSRF: HMAC of the session id
const CSRF_SECRET = ADMIN_TOKEN || "boot"; // tied to the admin token
function csrfToken(sid) {
  return crypto.createHmac("sha256", CSRF_SECRET).update(sid).digest("hex").slice(0, 32);
}
function csrfFieldHtml(sid) {
  return `<input type="hidden" name="_csrf" value="${csrfToken(sid)}">`;
}
function safeEqual(a, b) {
  const ba = Buffer.from(String(a || ""));
  const bb = Buffer.from(String(b || ""));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

// =============================================================================
// Worker helpers
// =============================================================================
async function workerFetch(path, opts = {}) {
  return fetch(`${ORDERS_WORKER_URL}${path}`, {
    ...opts,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${ORDERS_API_KEY}`,
      ...(opts.headers || {})
    }
  });
}
async function saveOrderToKV(order) {
  try {
    const res = await workerFetch("/orders/save", { method: "POST", body: JSON.stringify(order) });
    if (!res.ok) console.error(`[kv-save] failed (${res.status}):`, await res.text());
  } catch (e) { console.error("[kv-save] error:", e.message); }
}
async function getOrderFromKV(order_id) {
  try {
    const res = await workerFetch(`/orders/get/${encodeURIComponent(order_id)}`);
    if (res.status === 404) return null;
    if (!res.ok) return null;
    return await res.json();
  } catch { return null; }
}
async function updateOrderInKV(payload) {
  const res = await workerFetch("/orders/update", { method: "POST", body: JSON.stringify(payload) });
  if (!res.ok) throw new Error(`Worker update failed (${res.status}): ${await res.text()}`);
  return res.json();
}
async function deleteOrderInKV(order_id) {
  const res = await workerFetch("/orders/delete", { method: "POST", body: JSON.stringify({ order_id }) });
  if (!res.ok) throw new Error(`Worker delete failed (${res.status}): ${await res.text()}`);
  return res.json();
}
async function updateServiceInKV(payload) {
  const res = await workerFetch("/services/update", { method: "POST", body: JSON.stringify(payload) });
  if (!res.ok) throw new Error(`Worker service update failed (${res.status}): ${await res.text()}`);
  return res.json();
}
async function deleteServiceInKV(service_id) {
  const res = await workerFetch("/services/delete", { method: "POST", body: JSON.stringify({ service_id }) });
  if (!res.ok) throw new Error(`Worker service delete failed (${res.status}): ${await res.text()}`);
  return res.json();
}
async function adminCreateServiceInKV(payload) {
  const res = await workerFetch("/services/admin-create", { method: "POST", body: JSON.stringify(payload) });
  if (!res.ok) throw new Error(`Worker admin-create failed (${res.status}): ${await res.text()}`);
  return res.json();
}

// =============================================================================
// Service email helper
// =============================================================================
async function sendServiceEmail(type, data) {
  if (!ORDER_EMAIL_TOKEN || !EMAIL_WORKER_URL) {
    console.log("[service-email] skipped — EMAIL_WORKER_URL or ORDER_EMAIL_TOKEN not set");
    return false;
  }
  try {
    const res = await fetch(`${EMAIL_WORKER_URL}/send-service-email`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${ORDER_EMAIL_TOKEN}` },
      body: JSON.stringify({ type, ...data })
    });
    if (!res.ok) { console.error(`[service-email] failed (${res.status}):`, await res.text()); return false; }
    console.log(`[service-email] ${type} sent to ${data.to} for ${data.service_id}`);
    return true;
  } catch (e) { console.error("[service-email] error:", e.message); return false; }
}

// =============================================================================
// Auth middleware (cookie session OR header token for API tools)
// =============================================================================
function getSidFromReq(req) {
  const cookies = parseCookies(req.headers.cookie || "");
  return cookies[COOKIE_NAME] || "";
}
function requireAdmin(req, res, next) {
  if (!ADMIN_TOKEN) return res.status(503).json({ error: "Admin endpoint disabled" });
  const sid = getSidFromReq(req);
  if (sid && isSessionValid(sid)) {
    req._sid = sid;
    return next();
  }
  // For programmatic API calls (curl/scripts), still allow header token
  const headerToken = req.headers["x-admin-token"];
  if (headerToken && safeEqual(headerToken, ADMIN_TOKEN)) {
    req._sid = ""; // header auth = no CSRF needed
    return next();
  }
  const wantsHtml = (req.headers.accept || "").includes("text/html");
  if (wantsHtml) return res.redirect("/login");
  return res.status(401).json({ error: "Unauthorized" });
}
function requireCsrf(req, res, next) {
  // Header-token auth (no cookie) is exempt from CSRF
  if (!req._sid) return next();
  const supplied = (req.body && req.body._csrf) || req.headers["x-csrf-token"] || "";
  if (!safeEqual(supplied, csrfToken(req._sid))) {
    return res.status(403).send("Invalid or missing CSRF token. <a href='/admin'>← Back</a>");
  }
  next();
}

// =============================================================================
// Helpers
// =============================================================================
function normalizeStatus(raw) {
  const s = (raw || "").toString().toUpperCase();
  if (s === "SUCCESS" || s === "PAID") return "Pending";
  if (s === "FAILED" || s === "CANCELED" || s === "CANCELLED") return "Cancelled";
  if (s === "REFUNDED") return "Refunded";
  if (s === "COMPLETED") return "Completed";
  return "Pending";
}
function statusBadgeHtml(status) {
  const s = (status || "Pending").toLowerCase();
  let bg = "rgba(245,158,11,.15)", color = "#fbbf24", label = "Pending";
  if (s === "completed") { bg = "rgba(22,163,74,.15)"; color = "#4ade80"; label = "Completed"; }
  else if (s === "cancelled" || s === "canceled" || s === "failed") { bg = "rgba(239,68,68,.15)"; color = "#f87171"; label = "Cancelled"; }
  else if (s === "refunded") { bg = "rgba(99,102,241,.15)"; color = "#a5b4fc"; label = "Refunded"; }
  return `<span style="display:inline-block;padding:4px 12px;border-radius:20px;background:${bg};color:${color};font-size:11px;font-weight:700;text-transform:uppercase">${label}</span>`;
}
function serviceBadgeHtml(status) {
  const map = {
    "Pending":     ["rgba(245,158,11,.15)", "#fbbf24"],
    "Reviewing":   ["rgba(59,130,246,.15)", "#60a5fa"],
    "Scheduled":   ["rgba(168,85,247,.15)", "#c084fc"],
    "In Progress": ["rgba(14,165,233,.15)", "#38bdf8"],
    "Completed":   ["rgba(22,163,74,.15)",  "#4ade80"],
    "Cancelled":   ["rgba(239,68,68,.15)",  "#f87171"]
  };
  const [bg, color] = map[status] || map["Pending"];
  return `<span style="display:inline-block;padding:4px 12px;border-radius:20px;background:${bg};color:${color};font-size:11px;font-weight:700;text-transform:uppercase">${status || "Pending"}</span>`;
}
function escapeHtml(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[c]));
}
function adminTabsHtml(active) {
  const tab = (href, label, isActive) =>
    `<a href="${href}" style="padding:8px 16px;border-radius:6px;text-decoration:none;font-size:13px;font-weight:600;${isActive ? "background:#dc2626;color:#fff" : "background:#1e293b;color:#e2e8f0;border:1px solid #334155"}">${label}</a>`;
  return `<div style="display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap">${tab("/admin","🛒 Orders",active==="orders")}${tab("/admin/services","🛠️ Service Requests",active==="services")}</div>`;
}
function dangerZoneFormHtml(action, label, sid) {
  return `
    <form class="card" method="POST" action="${action}"
      onsubmit="return confirm('Permanently delete this ${label}? This cannot be undone.')"
      style="border-color:#7f1d1d">
      ${csrfFieldHtml(sid)}
      <strong style="font-size:16px;color:#f87171">⚠ Danger Zone</strong>
      <p style="color:#94a3b8;font-size:13px;margin:8px 0 12px">Type <code>DELETE</code> below to permanently remove this ${label} from KV.</p>
      <input name="confirm" placeholder="Type DELETE to confirm" required autocomplete="off"
        style="width:100%;padding:10px 12px;background:#0f172a;border:1px solid #7f1d1d;border-radius:6px;color:#fff;font-family:inherit;box-sizing:border-box">
      <button type="submit" style="margin-top:12px;padding:10px 18px;background:#7f1d1d;color:#fff;border:none;border-radius:6px;font-weight:700;cursor:pointer">Delete ${label}</button>
    </form>`;
}

// Strip prototype-pollution keys from a flat object
function safeClone(obj) {
  const out = {};
  for (const k of Object.keys(obj || {})) {
    if (k === "__proto__" || k === "constructor" || k === "prototype") continue;
    out[k] = obj[k];
  }
  return out;
}

// =============================================================================
// Public root
// =============================================================================
app.get("/", (req, res) => res.send("DirectPay backend running"));

// =============================================================================
// Login portal
// =============================================================================
app.get("/login", (req, res) => {
  const error = req.query.err === "1" ? `<div class="err">Invalid password. Try again.</div>`
              : req.query.err === "2" ? `<div class="err">Too many attempts. Wait a few minutes.</div>` : "";
  res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>RedTrex Admin Login</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>
      *{box-sizing:border-box}body{font-family:system-ui,Arial;background:linear-gradient(135deg,#0f172a,#1e1b4b);color:#e2e8f0;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
      .card{background:#1e293b;padding:36px 32px;border-radius:14px;width:100%;max-width:380px;box-shadow:0 20px 60px rgba(0,0,0,.4);border:1px solid #334155}
      h1{color:#f87171;margin:0 0 6px;font-size:24px}p{color:#94a3b8;margin:0 0 24px;font-size:14px}
      label{display:block;font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px}
      input[type=password]{width:100%;padding:12px 14px;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#fff;font-size:14px;outline:none}
      input[type=password]:focus{border-color:#f87171}
      button{width:100%;margin-top:18px;padding:13px;background:#f87171;color:#0f172a;border:none;border-radius:8px;font-weight:700;font-size:14px;cursor:pointer;text-transform:uppercase;letter-spacing:.5px}
      button:hover{background:#fca5a5}
      .err{background:#7f1d1d;color:#fee2e2;padding:10px 14px;border-radius:6px;margin-bottom:18px;font-size:13px}
      .logo{font-size:32px;margin-bottom:8px}
    </style></head><body>
    <form class="card" method="POST" action="/login">
      <div class="logo">🛒</div><h1>RedTrex Admin</h1>
      <p>Enter your admin password to view orders.</p>${error}
      <label for="pw">Password</label>
      <input id="pw" type="password" name="token" autofocus autocomplete="current-password" required>
      <button type="submit">Sign In</button>
    </form></body></html>`);
});

app.post("/login", loginLimiter, (req, res) => {
  const supplied = (req.body.token || "").toString();
  if (!ADMIN_TOKEN || !safeEqual(supplied, ADMIN_TOKEN)) {
    // Constant-ish delay to slow brute-force probes
    return setTimeout(() => res.redirect("/login?err=1"), 400);
  }
  const sid = createSession(clientIp(req));
  setAdminCookie(res, sid);
  res.redirect("/admin");
});

app.get("/logout", (req, res) => {
  destroySession(getSidFromReq(req));
  clearAdminCookie(res);
  res.redirect("/login");
});

// =============================================================================
// Admin: list orders
// =============================================================================
app.get("/admin", requireAdmin, async (req, res) => {
  let all = [], fetchError = null;
  try {
    const r = await workerFetch("/orders/list?limit=500");
    const data = await r.json();
    all = data.orders || [];
  } catch (e) { fetchError = e.message; }

  const deleted = req.query.deleted ? `<div style="background:rgba(22,163,74,.15);color:#4ade80;border:1px solid rgba(22,163,74,.3);padding:10px 14px;border-radius:6px;margin-bottom:14px">✓ Deleted ${escapeHtml(req.query.deleted)}</div>` : "";
  const sid = req._sid;

  const rows = all.map(o => {
    const items = Array.isArray(o.items) && o.items.length > 0
      ? o.items.map(it => `${escapeHtml(it.name)} ×${it.quantity || it.qty || 1}`).join("<br>")
      : `${escapeHtml(o.product_name || "—")} ×${o.qty || 1}`;
    return `
      <tr>
        <td><a href="/admin/order/${encodeURIComponent(o.order_id)}" style="color:#f87171;text-decoration:none"><code>${escapeHtml(o.order_id)}</code></a></td>
        <td>${new Date(o.ts).toLocaleString()}</td>
        <td>${items}</td>
        <td>LKR ${o.amount}</td>
        <td>${escapeHtml(o.coupon_code || "-")}</td>
        <td>${escapeHtml(o.customer?.first_name || "")} ${escapeHtml(o.customer?.last_name || "")}<br>
            <small style="color:#94a3b8">${escapeHtml(o.customer?.email || "")}<br>${escapeHtml(o.customer?.phone || "")}</small></td>
        <td>${statusBadgeHtml(o.status)}</td>
        <td><a href="/admin/order/${encodeURIComponent(o.order_id)}" style="background:#dc2626;color:#fff;padding:6px 12px;border-radius:6px;text-decoration:none;font-size:12px;font-weight:700">Manage</a></td>
      </tr>`;
  }).join("");

  res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>RedTrex Orders</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>
      body{font-family:system-ui,Arial;background:#0f172a;color:#e2e8f0;padding:24px;margin:0}
      .head{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:10px}
      h1{color:#f87171;margin:0}
      .logout{background:#334155;color:#e2e8f0;padding:8px 14px;border-radius:6px;text-decoration:none;font-size:13px;border:1px solid #475569}
      .logout:hover{background:#475569}
      .err{background:#7f1d1d;color:#fee2e2;padding:10px 14px;border-radius:6px;margin-bottom:14px}
      table{width:100%;border-collapse:collapse;background:#1e293b;border-radius:8px;overflow:hidden}
      th,td{padding:10px 12px;text-align:left;border-bottom:1px solid #334155;font-size:13px;vertical-align:top}
      th{background:#0f172a;color:#94a3b8;text-transform:uppercase;font-size:11px}
      tr:hover td{background:#283548}
      code{background:#0f172a;padding:2px 6px;border-radius:4px;font-size:11px}
    </style></head><body>
    ${adminTabsHtml("orders")}
    ${deleted}
    <div class="head">
      <h1>🛒 RedTrex Orders <small style="font-size:14px;font-weight:400;color:#94a3b8">(${all.length} stored)</small></h1>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <a href="/admin/orders/new" style="background:#dc2626;color:#fff;padding:8px 14px;border-radius:6px;text-decoration:none;font-size:13px;font-weight:700">+ New Manual Order</a>
        <form method="POST" action="/admin/seed-test" style="margin:0">
          ${csrfFieldHtml(sid)}
          <button type="submit" style="background:#16a34a;color:#fff;padding:8px 14px;border:none;border-radius:6px;font-size:13px;font-weight:700;cursor:pointer">+ Test Order</button>
        </form>
        <a class="logout" href="/logout">Sign Out</a>
      </div>
    </div>
    ${fetchError ? `<div class="err">⚠ Could not reach Cloudflare KV: ${escapeHtml(fetchError)}</div>` : ""}
    <table>
      <thead><tr><th>Order ID</th><th>Time</th><th>Items</th><th>Amount</th><th>Coupon</th><th>Customer</th><th>Status</th><th></th></tr></thead>
      <tbody>${rows || '<tr><td colspan="8" style="text-align:center;padding:40px;color:#64748b">No orders yet</td></tr>'}</tbody>
    </table></body></html>`);
});

app.post("/admin/seed-test", requireAdmin, requireCsrf, async (req, res) => {
  const rand = Math.random().toString(36).slice(2, 7).toUpperCase();
  const order_id = `ORD-TEST-${rand}`;
  await saveOrderToKV({
    ts: Date.now(), order_id, amount: 4500,
    items: [
      { name: "Windows 11 Pro (TEST)", quantity: 1 },
      { name: "EaseUS Data Recovery (TEST)", quantity: 1 }
    ],
    coupon_code: "TESTCOUPON10",
    customer: { first_name: "Test", last_name: "Customer", email: "test@redtrex.com", phone: "+94712622012" },
    status: "Pending"
  });
  console.log(`[seed-test] created ${order_id}`);
  res.redirect(`/admin/order/${encodeURIComponent(order_id)}?saved=1`);
});

// =============================================================================
// Admin: NEW manual order form (for bank transfers, crypto, QR pay, etc.)
// =============================================================================
app.get("/admin/orders/new", requireAdmin, (req, res) => {
  const sid = req._sid;
  const err = req.query.err ? `<div style="background:#7f1d1d;color:#fee2e2;padding:10px 14px;border-radius:6px;margin-bottom:14px">⚠ ${escapeHtml(req.query.err)}</div>` : "";
  const methods = ["Bank Transfer", "Bybit Pay", "Binance Pay", "QR Pay", "Cash", "Card", "Other"];
  res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>New Manual Order</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>
      body{font-family:system-ui,Arial;background:#0f172a;color:#e2e8f0;padding:24px;margin:0 auto;max-width:760px}
      a.back{color:#f87171;text-decoration:none;font-size:13px;display:inline-block;margin-bottom:14px}
      h1{font-size:22px;margin:0 0 14px;color:#f87171}
      .card{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:20px;margin-bottom:16px}
      label{display:block;font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:.5px;margin:14px 0 6px;font-weight:600}
      input,select,textarea{width:100%;padding:10px 12px;background:#0f172a;border:1px solid #334155;border-radius:6px;color:#fff;font-size:14px;font-family:inherit;outline:none;box-sizing:border-box}
      textarea{min-height:90px;resize:vertical}
      input:focus,select:focus,textarea:focus{border-color:#f87171}
      .btn{display:inline-block;padding:11px 22px;background:#dc2626;color:#fff;border:none;border-radius:6px;font-weight:700;font-size:14px;cursor:pointer;text-transform:uppercase;letter-spacing:.5px}
      .btn:hover{background:#b91c1c}
      .grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
      @media(max-width:600px){.grid{grid-template-columns:1fr}}
      small{color:#64748b;font-size:12px}
    </style></head><body>
    <a class="back" href="/admin">← Back to all orders</a>
    <h1>➕ Create Manual Order</h1>
    ${err}
    <p style="color:#94a3b8;font-size:14px;margin:0 0 16px">Use this when a customer pays you directly (bank transfer, Bybit/Binance, QR, cash). Record the payment reference so it's traceable, then deliver the keys when ready.</p>
    <form class="card" method="POST" action="/admin/orders/new">
      ${csrfFieldHtml(sid)}

      <strong style="font-size:15px">Customer</strong>
      <div class="grid">
        <div><label>First Name *</label><input name="first_name" required maxlength="60"></div>
        <div><label>Last Name *</label><input name="last_name" required maxlength="60"></div>
      </div>
      <div class="grid">
        <div><label>Email *</label><input type="email" name="email" required maxlength="160"></div>
        <div><label>Phone *</label><input name="phone" required maxlength="30" placeholder="+947..."></div>
      </div>

      <hr style="border:none;border-top:1px solid #334155;margin:20px 0">
      <strong style="font-size:15px">Order Items</strong>
      <label>Product Name *</label>
      <input name="product_name" required maxlength="200" placeholder="e.g. Windows 11 Pro">
      <div class="grid">
        <div><label>Quantity *</label><input type="number" name="qty" min="1" max="100" value="1" required></div>
        <div><label>Total Amount (LKR) *</label><input type="number" name="amount" min="10" max="500000" step="0.01" required placeholder="e.g. 4500"></div>
      </div>

      <hr style="border:none;border-top:1px solid #334155;margin:20px 0">
      <strong style="font-size:15px">Payment</strong>
      <div class="grid">
        <div><label>Payment Method *</label><select name="payment_method" required>${methods.map(m => `<option value="${m}">${m}</option>`).join("")}</select></div>
        <div><label>Payment Reference / TXID *</label><input name="payment_reference" required maxlength="200" placeholder="Bank ref / Tx hash / Slip #"></div>
      </div>

      <hr style="border:none;border-top:1px solid #334155;margin:20px 0">
      <strong style="font-size:15px">Fulfillment</strong>
      <div class="grid">
        <div><label>Initial Status</label><select name="status">
          <option value="Pending" selected>Pending (payment confirmed, keys not yet sent)</option>
          <option value="Completed">Completed (keys ready to email)</option>
          <option value="Cancelled">Cancelled</option>
          <option value="Refunded">Refunded</option>
        </select></div>
        <div><label>Coupon Used <small>(optional)</small></label><input name="coupon_code" maxlength="50" placeholder="—"></div>
      </div>
      <label>Product Keys <small>(one per line — only sent if status is Completed)</small></label>
      <textarea name="product_keys" placeholder="XXXXX-XXXXX-XXXXX-XXXXX-XXXXX" style="font-family:'DM Mono',monospace,Courier"></textarea>
      <label>Admin Note <small>(internal — not visible to customer)</small></label>
      <textarea name="admin_note" placeholder="e.g. Bank slip received via WhatsApp 2026-05-05"></textarea>

      <div style="margin-top:18px"><button class="btn" type="submit">Create Order</button></div>
    </form>
  </body></html>`);
});

app.post("/admin/orders/new", requireAdmin, requireCsrf, async (req, res) => {
  try {
    const b = safeClone(req.body);
    const first_name = String(b.first_name || "").slice(0, 60).trim();
    const last_name  = String(b.last_name  || "").slice(0, 60).trim();
    const email      = String(b.email      || "").slice(0, 160).trim();
    const phone      = String(b.phone      || "").slice(0, 30).trim();
    const product_name = String(b.product_name || "").slice(0, MAX_ITEM_NAME).trim();
    const qty = Math.max(1, Math.min(100, Number(b.qty) || 1));
    const amount = Number(b.amount);
    const payment_method = String(b.payment_method || "Other").slice(0, 50);
    const payment_reference = String(b.payment_reference || "").slice(0, 200).trim();
    const coupon_code = b.coupon_code ? String(b.coupon_code).slice(0, 50).trim() : null;
    const status = ["Pending", "Completed", "Cancelled", "Refunded"].includes(b.status) ? b.status : "Pending";
    const admin_note = String(b.admin_note || "").slice(0, 2000);
    const keysRaw = String(b.product_keys || "");
    const product_keys = keysRaw.split(/\r?\n/).map(s => s.trim()).filter(Boolean);

    if (!first_name || !last_name) throw new Error("Name required");
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error("Valid email required");
    if (phone.length < 7) throw new Error("Valid phone required");
    if (!product_name) throw new Error("Product name required");
    if (!Number.isFinite(amount) || amount < MIN_AMOUNT_LKR || amount > MAX_AMOUNT_LKR)
      throw new Error(`Amount must be between LKR ${MIN_AMOUNT_LKR} and LKR ${MAX_AMOUNT_LKR}`);
    if (!payment_reference) throw new Error("Payment reference required");

    const order_id = `ORD-MAN-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(3).toString("hex").toUpperCase()}`;
    const order = {
      ts: Date.now(), order_id, amount, product_name, qty,
      items: [{ name: product_name, quantity: qty }],
      coupon_code,
      customer: { first_name, last_name, email, phone },
      status,
      payment_method,
      payment_reference,
      admin_note,
      created_by: "admin",
      paid_at: Date.now()
    };
    if (product_keys.length) order.product_keys = product_keys;

    await saveOrderToKV(order);
    console.log(`[admin] manual order ${order_id} | ${product_name} ×${qty} | LKR ${amount} | ${payment_method} ref=${payment_reference}`);

    // Auto-email keys if Completed and keys provided
    let emailed = false;
    if (status === "Completed" && product_keys.length && email && ORDER_EMAIL_TOKEN) {
      try {
        const r = await fetch(`${EMAIL_WORKER_URL}/send-order-email`, {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${ORDER_EMAIL_TOKEN}` },
          body: JSON.stringify({
            to: email,
            customer_name: `${first_name} ${last_name}`.trim(),
            order_id, items: order.items, product_keys, amount
          })
        });
        if (r.ok) { emailed = true; console.log(`[email] sent to ${email} for ${order_id}`); }
        else console.error(`[email] failed (${r.status}):`, await r.text());
      } catch (e) { console.error("[email] error:", e.message); }
    }

    res.redirect(`/admin/order/${encodeURIComponent(order_id)}?saved=1${emailed ? "&emailed=1" : ""}`);
  } catch (e) {
    res.redirect(`/admin/orders/new?err=${encodeURIComponent(e.message)}`);
  }
});

app.get("/admin/order/:id", requireAdmin, async (req, res) => {
  let order = null, error = null;
  try {
    const r = await workerFetch(`/orders/get/${encodeURIComponent(req.params.id)}`);
    if (r.status === 404)
      return res.status(404).send(`<p style="font-family:system-ui;padding:30px;color:#fff;background:#0f172a">Order not found. <a href="/admin" style="color:#f87171">← Back</a></p>`);
    order = await r.json();
  } catch (e) { error = e.message; }
  if (!order) return res.send(`<p style="color:red;font-family:system-ui">Error: ${escapeHtml(error)}</p>`);

  const sid = req._sid;
  const success = req.query.saved === "1" ? `<div class="ok">✓ Order updated successfully.</div>` : "";
  const emailed = req.query.emailed === "1" ? `<div class="ok" style="background:rgba(99,102,241,.15);color:#a5b4fc;border-color:rgba(99,102,241,.3)">📧 Customer notified by email.</div>` : "";
  const delerr  = req.query.delerr === "1" ? `<div class="err" style="background:#7f1d1d;color:#fee2e2;padding:10px 14px;border-radius:6px;margin-bottom:14px">⚠ You must type <code>DELETE</code> to confirm deletion.</div>` : "";
  const items = Array.isArray(order.items) && order.items.length > 0 ? order.items : [{ name: order.product_name || "Item", quantity: order.qty || 1 }];
  const keys = Array.isArray(order.product_keys) ? order.product_keys : [];
  const keysText = keys.join("\n");

  res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Manage Order</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>
      body{font-family:system-ui,Arial;background:#0f172a;color:#e2e8f0;padding:24px;margin:0 auto;max-width:760px}
      a.back{color:#f87171;text-decoration:none;font-size:13px;display:inline-block;margin-bottom:14px}
      h1{font-size:22px;margin:0 0 10px;color:#f87171}
      h1 code{font-family:monospace;font-size:16px;color:#e2e8f0;background:#1e293b;padding:4px 8px;border-radius:4px}
      .card{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:20px;margin-bottom:16px}
      .row{display:flex;justify-content:space-between;padding:6px 0;font-size:14px}
      .row span:first-child{color:#94a3b8}
      .row.items{flex-direction:column}
      .row.items .item{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px dashed #334155}
      .row.items .item:last-child{border:none}
      label{display:block;font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:.5px;margin:14px 0 6px;font-weight:600}
      select,textarea,input[type=text],input[type=number]{width:100%;padding:10px 12px;background:#0f172a;border:1px solid #334155;border-radius:6px;color:#fff;font-size:14px;font-family:inherit;outline:none;box-sizing:border-box}
      textarea{min-height:120px;font-family:'DM Mono',monospace,Courier;resize:vertical}
      select:focus,textarea:focus,input:focus{border-color:#f87171}
      .btn{display:inline-block;padding:11px 22px;background:#dc2626;color:#fff;border:none;border-radius:6px;font-weight:700;font-size:14px;cursor:pointer;text-transform:uppercase;letter-spacing:.5px}
      .btn:hover{background:#b91c1c}
      .ok{background:rgba(22,163,74,.15);color:#4ade80;border:1px solid rgba(22,163,74,.3);padding:10px 14px;border-radius:6px;margin-bottom:14px}
      small{color:#64748b;font-size:12px}
    </style></head><body>
    <a class="back" href="/admin">← Back to all orders</a>
    <h1>Manage Order: <code>${escapeHtml(order.order_id)}</code></h1>
    ${success}${emailed}${delerr}
    <div class="card">
      <div class="row"><span>Status</span><span>${statusBadgeHtml(order.status)}</span></div>
      <div class="row"><span>Placed</span><span>${new Date(order.ts).toLocaleString()}</span></div>
      ${order.paid_at ? `<div class="row"><span>Paid at</span><span>${new Date(order.paid_at).toLocaleString()}</span></div>` : ""}
      <div class="row"><span>Amount</span><span><strong>LKR ${order.amount}</strong></span></div>
      ${order.coupon_code ? `<div class="row"><span>Coupon</span><span>${escapeHtml(order.coupon_code)}</span></div>` : ""}
      <div class="row"><span>Customer</span><span>${escapeHtml(order.customer?.first_name || "")} ${escapeHtml(order.customer?.last_name || "")}</span></div>
      <div class="row"><span>Email</span><span>${escapeHtml(order.customer?.email || "—")}</span></div>
      <div class="row"><span>Phone</span><span>${escapeHtml(order.customer?.phone || "—")}</span></div>
      ${order.payment_method ? `<div class="row"><span>Payment Method</span><span><strong>${escapeHtml(order.payment_method)}</strong></span></div>` : ""}
      ${order.payment_reference ? `<div class="row"><span>Payment Reference</span><span><code style="background:#0f172a;padding:2px 8px;border-radius:4px;font-size:12px">${escapeHtml(order.payment_reference)}</code></span></div>` : ""}
      ${order.admin_note ? `<div class="row"><span>Admin Note</span><span style="white-space:pre-wrap;text-align:right">${escapeHtml(order.admin_note)}</span></div>` : ""}
      ${order.created_by === "admin" ? `<div class="row"><span>Created By</span><span style="color:#a5b4fc">Admin (manual)</span></div>` : ""}
    </div>

    <div class="card">
      <strong>Items</strong>
      <div class="row items" style="margin-top:8px">
        ${items.map(it => `<div class="item"><span>${escapeHtml(it.name)}</span><span>×${it.quantity || it.qty || 1}</span></div>`).join("")}
      </div>
    </div>

    <form class="card" method="POST" action="/admin/order/${encodeURIComponent(order.order_id)}">
      ${csrfFieldHtml(sid)}
      <strong style="font-size:16px">Update Order</strong>
      <label for="status">Status</label>
      <select name="status" id="status">
        <option value="Pending"   ${order.status === "Pending"   ? "selected" : ""}>Pending (paid, awaiting fulfillment)</option>
        <option value="Completed" ${order.status === "Completed" ? "selected" : ""}>Completed (keys delivered)</option>
        <option value="Cancelled" ${order.status === "Cancelled" ? "selected" : ""}>Cancelled</option>
        <option value="Refunded"  ${order.status === "Refunded"  ? "selected" : ""}>Refunded</option>
      </select>
      <label for="product_keys">Product Keys <small>(one per line — visible to customer when status is Completed)</small></label>
      <textarea name="product_keys" id="product_keys" placeholder="XXXXX-XXXXX-XXXXX-XXXXX-XXXXX">${escapeHtml(keysText)}</textarea>
      <p style="margin:12px 0 0;font-size:13px;color:#94a3b8">💡 Setting status to <strong>Completed</strong> will automatically email the customer their keys.</p>
      <div style="margin-top:16px"><button class="btn" type="submit">Save Changes</button></div>
    </form>

    ${dangerZoneFormHtml(`/admin/order/${encodeURIComponent(order.order_id)}/delete`, "Order", sid)}
  </body></html>`);
});

app.post("/admin/order/:id", requireAdmin, requireCsrf, async (req, res) => {
  const order_id = req.params.id;
  const status = (req.body.status || "").toString();
  const keysRaw = (req.body.product_keys || "").toString();
  const product_keys = keysRaw.split(/\r?\n/).map(s => s.trim()).filter(Boolean);

  try {
    const previous = await getOrderFromKV(order_id);
    await updateOrderInKV({ order_id, status, product_keys });

    let emailed = false;
    const becameCompleted = status === "Completed" && (!previous || previous.status !== "Completed");
    if (becameCompleted && product_keys.length > 0 && previous?.customer?.email && ORDER_EMAIL_TOKEN) {
      try {
        const emailRes = await fetch(`${EMAIL_WORKER_URL}/send-order-email`, {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${ORDER_EMAIL_TOKEN}` },
          body: JSON.stringify({
            to: previous.customer.email,
            customer_name: `${previous.customer.first_name || ""} ${previous.customer.last_name || ""}`.trim() || "Customer",
            order_id,
            items: previous.items || [],
            product_keys,
            amount: previous.amount
          })
        });
        if (!emailRes.ok) console.error(`[email] failed (${emailRes.status}):`, await emailRes.text());
        else { console.log(`[email] sent to ${previous.customer.email} for ${order_id}`); emailed = true; }
      } catch (e) { console.error("[email] error:", e.message); }
    }

    res.redirect(`/admin/order/${encodeURIComponent(order_id)}?saved=1${emailed ? "&emailed=1" : ""}`);
  } catch (e) {
    res.status(500).send(`<p style="color:red;font-family:system-ui;padding:24px">Update failed: ${escapeHtml(e.message)} <a href="/admin/order/${encodeURIComponent(order_id)}">← Try again</a></p>`);
  }
});

app.post("/admin/order/:id/delete", requireAdmin, requireCsrf, async (req, res) => {
  const order_id = req.params.id;
  const confirm = (req.body.confirm || "").toString().trim().toUpperCase();
  if (confirm !== "DELETE") return res.redirect(`/admin/order/${encodeURIComponent(order_id)}?delerr=1`);
  try {
    await deleteOrderInKV(order_id);
    console.log(`[admin] deleted order ${order_id}`);
    res.redirect(`/admin?deleted=${encodeURIComponent(order_id)}`);
  } catch (e) {
    res.status(500).send(`<p style="color:red;font-family:system-ui;padding:24px">Delete failed: ${escapeHtml(e.message)} <a href="/admin/order/${encodeURIComponent(order_id)}">← Back</a></p>`);
  }
});

// =============================================================================
// Admin: list service requests
// =============================================================================
app.get("/admin/services", requireAdmin, async (req, res) => {
  let all = [], fetchError = null;
  try {
    const r = await workerFetch("/services/list?limit=500");
    const data = await r.json();
    all = data.services || [];
  } catch (e) { fetchError = e.message; }

  const sid = req._sid;
  const deleted = req.query.deleted ? `<div style="background:rgba(22,163,74,.15);color:#4ade80;border:1px solid rgba(22,163,74,.3);padding:10px 14px;border-radius:6px;margin-bottom:14px">✓ Deleted ${escapeHtml(req.query.deleted)}</div>` : "";
  const created = req.query.newsvc ? `<div style="background:rgba(22,163,74,.15);color:#4ade80;border:1px solid rgba(22,163,74,.3);padding:10px 14px;border-radius:6px;margin-bottom:14px">✓ New service request created. Share the SVC-ID with the customer.</div>` : "";

  const rows = all.map(s => `
    <tr>
      <td><a href="/admin/service/${encodeURIComponent(s.service_id)}" style="color:#f87171;text-decoration:none"><code>${escapeHtml(s.service_id)}</code></a>${s.created_by === "admin" ? ' <small style="color:#a5b4fc">(admin)</small>' : ""}</td>
      <td>${new Date(s.ts).toLocaleString()}</td>
      <td>${escapeHtml(s.customer?.first_name || "")} ${escapeHtml(s.customer?.last_name || "")}<br>
          <small style="color:#94a3b8">${escapeHtml(s.customer?.email || "")}<br>${escapeHtml(s.customer?.phone || "")}</small></td>
      <td>${escapeHtml(s.service_type || "—")}</td>
      <td><small style="color:#cbd5e1;line-height:1.4">${escapeHtml((s.description || "").slice(0, 90))}${(s.description || "").length > 90 ? "…" : ""}</small></td>
      <td>${serviceBadgeHtml(s.status)}</td>
      <td><a href="/admin/service/${encodeURIComponent(s.service_id)}" style="background:#dc2626;color:#fff;padding:6px 12px;border-radius:6px;text-decoration:none;font-size:12px;font-weight:700">Manage</a></td>
    </tr>`).join("");

  res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>RedTrex Service Requests</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>
      body{font-family:system-ui,Arial;background:#0f172a;color:#e2e8f0;padding:24px;margin:0}
      .head{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:10px}
      h1{color:#f87171;margin:0}
      .logout{background:#334155;color:#e2e8f0;padding:8px 14px;border-radius:6px;text-decoration:none;font-size:13px;border:1px solid #475569}
      .logout:hover{background:#475569}
      .err{background:#7f1d1d;color:#fee2e2;padding:10px 14px;border-radius:6px;margin-bottom:14px}
      table{width:100%;border-collapse:collapse;background:#1e293b;border-radius:8px;overflow:hidden}
      th,td{padding:10px 12px;text-align:left;border-bottom:1px solid #334155;font-size:13px;vertical-align:top}
      th{background:#0f172a;color:#94a3b8;text-transform:uppercase;font-size:11px}
      tr:hover td{background:#283548}
      code{background:#0f172a;padding:2px 6px;border-radius:4px;font-size:11px}
    </style></head><body>
    ${adminTabsHtml("services")}
    ${deleted}${created}
    <div class="head">
      <h1>🛠️ Service Requests <small style="font-size:14px;font-weight:400;color:#94a3b8">(${all.length} stored)</small></h1>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <a href="/admin/services/new" style="background:#dc2626;color:#fff;padding:8px 14px;border-radius:6px;text-decoration:none;font-size:13px;font-weight:700">+ New Service Request</a>
        <form method="POST" action="/admin/services/seed-test" style="margin:0">
          ${csrfFieldHtml(sid)}
          <button type="submit" style="background:#16a34a;color:#fff;padding:8px 14px;border:none;border-radius:6px;font-size:13px;font-weight:700;cursor:pointer">+ Test Request</button>
        </form>
        <a class="logout" href="/logout">Sign Out</a>
      </div>
    </div>
    ${fetchError ? `<div class="err">⚠ Could not reach Cloudflare KV: ${escapeHtml(fetchError)}</div>` : ""}
    <table>
      <thead><tr><th>Reference</th><th>Submitted</th><th>Customer</th><th>Service</th><th>Description</th><th>Status</th><th></th></tr></thead>
      <tbody>${rows || '<tr><td colspan="7" style="text-align:center;padding:40px;color:#64748b">No service requests yet</td></tr>'}</tbody>
    </table></body></html>`);
});

app.post("/admin/services/seed-test", requireAdmin, requireCsrf, async (req, res) => {
  try {
    const r = await fetch(`${ORDERS_WORKER_URL}/services/create`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        first_name: "Test", last_name: "Customer",
        email: "test@redtrex.com", phone: "+94712622012",
        service_type: "IT Support",
        description: "This is a seeded test request to verify the admin workflow end-to-end."
      })
    });
    const data = await r.json();
    if (!data.created) return res.status(500).send("Seed failed: " + JSON.stringify(data));
    res.redirect(`/admin/service/${encodeURIComponent(data.service_id)}?saved=1`);
  } catch (e) {
    res.status(500).send("Seed error: " + escapeHtml(e.message));
  }
});

// =============================================================================
// Admin: NEW service request form
// =============================================================================
app.get("/admin/services/new", requireAdmin, (req, res) => {
  const sid = req._sid;
  const err = req.query.err ? `<div style="background:#7f1d1d;color:#fee2e2;padding:10px 14px;border-radius:6px;margin-bottom:14px">⚠ ${escapeHtml(req.query.err)}</div>` : "";
  res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>New Service Request</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>
      body{font-family:system-ui,Arial;background:#0f172a;color:#e2e8f0;padding:24px;margin:0 auto;max-width:760px}
      a.back{color:#f87171;text-decoration:none;font-size:13px;display:inline-block;margin-bottom:14px}
      h1{font-size:22px;margin:0 0 14px;color:#f87171}
      .card{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:20px;margin-bottom:16px}
      label{display:block;font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:.5px;margin:14px 0 6px;font-weight:600}
      input,select,textarea{width:100%;padding:10px 12px;background:#0f172a;border:1px solid #334155;border-radius:6px;color:#fff;font-size:14px;font-family:inherit;outline:none;box-sizing:border-box}
      textarea{min-height:120px;resize:vertical}
      input:focus,select:focus,textarea:focus{border-color:#f87171}
      .btn{display:inline-block;padding:11px 22px;background:#dc2626;color:#fff;border:none;border-radius:6px;font-weight:700;font-size:14px;cursor:pointer;text-transform:uppercase;letter-spacing:.5px}
      .btn:hover{background:#b91c1c}
      .grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
      @media(max-width:600px){.grid{grid-template-columns:1fr}}
      small{color:#64748b;font-size:12px}
    </style></head><body>
    <a class="back" href="/admin/services">← Back to all requests</a>
    <h1>➕ Create New Service Request</h1>
    ${err}
    <p style="color:#94a3b8;font-size:14px;margin:0 0 16px">Use this when a customer contacts you by phone/WhatsApp instead of the website. They'll be able to track it using their email + the SVC-ID you give them.</p>
    <form class="card" method="POST" action="/admin/services/new">
      ${csrfFieldHtml(sid)}
      <div class="grid">
        <div><label>First Name *</label><input name="first_name" required maxlength="60"></div>
        <div><label>Last Name *</label><input name="last_name" required maxlength="60"></div>
      </div>
      <div class="grid">
        <div><label>Email *</label><input type="email" name="email" required maxlength="160"></div>
        <div><label>Phone *</label><input name="phone" required maxlength="30" placeholder="+947..."></div>
      </div>

      <label>Service Type *</label>
      <select name="service_type" required>${SERVICE_TYPES.map(t => `<option value="${t}">${t}</option>`).join("")}</select>

      <label>Description *</label>
      <textarea name="description" required minlength="15" maxlength="2500" placeholder="What does the customer need?"></textarea>

      <div class="grid">
        <div><label>Preferred Date <small>(optional)</small></label><input name="preferred_date" placeholder="e.g. Saturday morning"></div>
        <div><label>Location <small>(optional)</small></label><input name="location" placeholder="Negombo / Remote"></div>
      </div>

      <div class="grid">
        <div><label>Initial Status</label><select name="status">${SERVICE_STATUSES.map(s => `<option value="${s}" ${s === "Pending" ? "selected" : ""}>${s}</option>`).join("")}</select></div>
        <div><label>Quote (LKR) <small>(optional)</small></label><input type="number" name="quote_amount" min="0" step="0.01" value="0"></div>
      </div>

      <label>Scheduled For <small>(optional, visible to customer)</small></label>
      <input name="scheduled_for" placeholder="e.g. Saturday 2026-05-10 at 2:00 PM">

      <label>Note to Customer <small>(optional, visible on tracking page)</small></label>
      <textarea name="admin_note" placeholder="Any message you want them to see when they track."></textarea>

      <div style="margin-top:18px"><button class="btn" type="submit">Create Request</button></div>
    </form>
  </body></html>`);
});

app.post("/admin/services/new", requireAdmin, requireCsrf, async (req, res) => {
  try {
    const b = safeClone(req.body);
    const payload = {
      first_name: String(b.first_name || "").slice(0, 60),
      last_name: String(b.last_name || "").slice(0, 60),
      email: String(b.email || "").slice(0, 160),
      phone: String(b.phone || "").slice(0, 30),
      service_type: SERVICE_TYPES.includes(b.service_type) ? b.service_type : "Custom",
      description: String(b.description || "").slice(0, 2500),
      preferred_date: String(b.preferred_date || "").slice(0, 120),
      location: String(b.location || "").slice(0, 250),
      status: SERVICE_STATUSES.includes(b.status) ? b.status : "Pending",
      scheduled_for: String(b.scheduled_for || "").slice(0, 200),
      admin_note: String(b.admin_note || "").slice(0, 2000),
      quote_amount: Math.max(0, Number(b.quote_amount) || 0)
    };
    const result = await adminCreateServiceInKV(payload);
    console.log(`[admin] created service ${result.service_id} for ${payload.email}`);

    let emailed = false;
    if (payload.email) {
      emailed = await sendServiceEmail("created", {
        to: payload.email,
        customer_name: `${payload.first_name} ${payload.last_name}`.trim() || "Customer",
        service_id: result.service_id,
        service_type: payload.service_type,
        description: payload.description,
        status: payload.status,
        admin_note: payload.admin_note,
        scheduled_for: payload.scheduled_for,
        quote_amount: payload.quote_amount
      });
    }
    res.redirect(`/admin/service/${encodeURIComponent(result.service_id)}?saved=1&newsvc=1${emailed ? "&emailed=1" : ""}`);
  } catch (e) {
    res.redirect(`/admin/services/new?err=${encodeURIComponent(e.message)}`);
  }
});

// =============================================================================
// Admin: single service request
// =============================================================================
app.get("/admin/service/:id", requireAdmin, async (req, res) => {
  let svc = null, error = null;
  try {
    const r = await workerFetch(`/services/get/${encodeURIComponent(req.params.id)}`);
    if (r.status === 404)
      return res.status(404).send(`<p style="font-family:system-ui;padding:30px;color:#fff;background:#0f172a">Request not found. <a href="/admin/services" style="color:#f87171">← Back</a></p>`);
    svc = await r.json();
  } catch (e) { error = e.message; }
  if (!svc) return res.send(`<p style="color:red;font-family:system-ui">Error: ${escapeHtml(error)}</p>`);

  const sid = req._sid;
  const success = req.query.saved === "1" ? `<div class="ok">✓ Request updated successfully.</div>` : "";
  const emailed = req.query.emailed === "1" ? `<div class="ok" style="background:rgba(99,102,241,.15);color:#a5b4fc;border-color:rgba(99,102,241,.3)">📧 Customer notified by email.</div>` : "";
  const newSvc  = req.query.newsvc === "1" ? `<div class="ok" style="background:rgba(99,102,241,.15);color:#a5b4fc;border-color:rgba(99,102,241,.3)">📬 Share these with the customer:<br><strong>SVC-ID:</strong> <code>${escapeHtml(svc.service_id)}</code><br><strong>Email:</strong> <code>${escapeHtml(svc.customer?.email || "")}</code><br>Tracking page: <a href="https://www.redtrex.com.lk/track-service" style="color:#a5b4fc">redtrex.com.lk/track-service</a></div>` : "";
  const delerr  = req.query.delerr === "1" ? `<div class="err" style="background:#7f1d1d;color:#fee2e2;padding:10px 14px;border-radius:6px;margin-bottom:14px">⚠ You must type <code>DELETE</code> to confirm deletion.</div>` : "";
  const statusOpts = SERVICE_STATUSES.map(s => `<option value="${s}" ${svc.status === s ? "selected" : ""}>${s}</option>`).join("");

  res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Manage Service Request</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>
      body{font-family:system-ui,Arial;background:#0f172a;color:#e2e8f0;padding:24px;margin:0 auto;max-width:760px}
      a.back{color:#f87171;text-decoration:none;font-size:13px;display:inline-block;margin-bottom:14px}
      h1{font-size:22px;margin:0 0 10px;color:#f87171}
      h1 code{font-family:monospace;font-size:16px;color:#e2e8f0;background:#1e293b;padding:4px 8px;border-radius:4px}
      .card{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:20px;margin-bottom:16px}
      .row{display:flex;justify-content:space-between;padding:6px 0;font-size:14px;gap:14px}
      .row span:first-child{color:#94a3b8;flex-shrink:0}
      .row span:last-child{text-align:right;word-break:break-word}
      .desc-box{background:#0f172a;border:1px solid #334155;border-radius:6px;padding:12px;margin-top:8px;white-space:pre-wrap;font-size:14px;line-height:1.55}
      label{display:block;font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:.5px;margin:14px 0 6px;font-weight:600}
      select,textarea,input[type=text],input[type=number]{width:100%;padding:10px 12px;background:#0f172a;border:1px solid #334155;border-radius:6px;color:#fff;font-size:14px;font-family:inherit;outline:none;box-sizing:border-box}
      textarea{min-height:100px;resize:vertical}
      select:focus,textarea:focus,input:focus{border-color:#f87171}
      .btn{display:inline-block;padding:11px 22px;background:#dc2626;color:#fff;border:none;border-radius:6px;font-weight:700;font-size:14px;cursor:pointer;text-transform:uppercase;letter-spacing:.5px}
      .btn:hover{background:#b91c1c}
      .ok{background:rgba(22,163,74,.15);color:#4ade80;border:1px solid rgba(22,163,74,.3);padding:10px 14px;border-radius:6px;margin-bottom:14px;line-height:1.7}
      small{color:#64748b;font-size:12px}
    </style></head><body>
    <a class="back" href="/admin/services">← Back to all requests</a>
    <h1>Service Request: <code>${escapeHtml(svc.service_id)}</code></h1>
    ${success}${emailed}${newSvc}${delerr}
    <div class="card">
      <div class="row"><span>Status</span><span>${serviceBadgeHtml(svc.status)}</span></div>
      <div class="row"><span>Submitted</span><span>${new Date(svc.ts).toLocaleString()}${svc.created_by === "admin" ? ' <small style="color:#a5b4fc">(by admin)</small>' : ""}</span></div>
      ${svc.updated_at ? `<div class="row"><span>Updated</span><span>${new Date(svc.updated_at).toLocaleString()}</span></div>` : ""}
      <div class="row"><span>Customer</span><span>${escapeHtml(svc.customer?.first_name || "")} ${escapeHtml(svc.customer?.last_name || "")}</span></div>
      <div class="row"><span>Email</span><span>${escapeHtml(svc.customer?.email || "—")}</span></div>
      <div class="row"><span>Phone</span><span>${escapeHtml(svc.customer?.phone || "—")}</span></div>
      <div class="row"><span>Service Type</span><span><strong>${escapeHtml(svc.service_type || "—")}</strong></span></div>
      ${svc.preferred_date ? `<div class="row"><span>Preferred</span><span>${escapeHtml(svc.preferred_date)}</span></div>` : ""}
      ${svc.location ? `<div class="row"><span>Location</span><span>${escapeHtml(svc.location)}</span></div>` : ""}
    </div>

    <div class="card">
      <strong>Description from customer</strong>
      <div class="desc-box">${escapeHtml(svc.description || "—")}</div>
    </div>

    <form class="card" method="POST" action="/admin/service/${encodeURIComponent(svc.service_id)}">
      ${csrfFieldHtml(sid)}
      <strong style="font-size:16px">Update Request</strong>
      <label for="status">Status</label>
      <select name="status" id="status">${statusOpts}</select>
      <label for="scheduled_for">Scheduled For <small>(free text — visible to customer)</small></label>
      <input type="text" name="scheduled_for" id="scheduled_for" value="${escapeHtml(svc.scheduled_for || "")}" placeholder="e.g. Saturday 2026-05-10 at 2:00 PM">
      <label for="quote_amount">Quote Amount (LKR) <small>(optional — shown on tracking page when &gt; 0)</small></label>
      <input type="number" name="quote_amount" id="quote_amount" min="0" step="0.01" value="${Number(svc.quote_amount) || 0}">
      <label for="admin_note">Note to Customer <small>(visible on the tracking page)</small></label>
      <textarea name="admin_note" id="admin_note" placeholder="e.g. We'll arrive Saturday 2pm. Please back up your data first.">${escapeHtml(svc.admin_note || "")}</textarea>
      <p style="margin:12px 0 0;font-size:13px;color:#94a3b8">💡 The customer can see your status, schedule, quote and note on the tracking page.</p>
      <div style="margin-top:16px"><button class="btn" type="submit">Save Changes</button></div>
    </form>

    ${dangerZoneFormHtml(`/admin/service/${encodeURIComponent(svc.service_id)}/delete`, "Request", sid)}
  </body></html>`);
});

app.post("/admin/service/:id", requireAdmin, requireCsrf, async (req, res) => {
  const service_id = req.params.id;
  const b = safeClone(req.body);
  const status = SERVICE_STATUSES.includes(b.status) ? b.status : "Pending";
  const admin_note = String(b.admin_note || "").slice(0, 2000);
  const scheduled_for = String(b.scheduled_for || "").slice(0, 200);
  const quote_amount = Math.max(0, Number(b.quote_amount) || 0);

  try {
    let previous = null;
    try {
      const r = await workerFetch(`/services/get/${encodeURIComponent(service_id)}`);
      if (r.ok) previous = await r.json();
    } catch (_) {}

    await updateServiceInKV({ service_id, status, admin_note, scheduled_for, quote_amount });

    let emailed = false;
    const statusChanged = previous && previous.status !== status;
    if (statusChanged && previous?.customer?.email) {
      emailed = await sendServiceEmail("updated", {
        to: previous.customer.email,
        customer_name: `${previous.customer.first_name || ""} ${previous.customer.last_name || ""}`.trim() || "Customer",
        service_id,
        service_type: previous.service_type || "",
        status,
        previous_status: previous.status,
        admin_note,
        scheduled_for,
        quote_amount
      });
    }

    res.redirect(`/admin/service/${encodeURIComponent(service_id)}?saved=1${emailed ? "&emailed=1" : ""}`);
  } catch (e) {
    res.status(500).send(`<p style="color:red;font-family:system-ui;padding:24px">Update failed: ${escapeHtml(e.message)} <a href="/admin/service/${encodeURIComponent(service_id)}">← Try again</a></p>`);
  }
});

app.post("/admin/service/:id/delete", requireAdmin, requireCsrf, async (req, res) => {
  const service_id = req.params.id;
  const confirm = (req.body.confirm || "").toString().trim().toUpperCase();
  if (confirm !== "DELETE") return res.redirect(`/admin/service/${encodeURIComponent(service_id)}?delerr=1`);
  try {
    await deleteServiceInKV(service_id);
    console.log(`[admin] deleted service ${service_id}`);
    res.redirect(`/admin/services?deleted=${encodeURIComponent(service_id)}`);
  } catch (e) {
    res.status(500).send(`<p style="color:red;font-family:system-ui;padding:24px">Delete failed: ${escapeHtml(e.message)} <a href="/admin/service/${encodeURIComponent(service_id)}">← Back</a></p>`);
  }
});

// =============================================================================
// JSON endpoints (admin only — header token works here)
// =============================================================================
app.get("/orders", requireAdmin, async (req, res) => {
  try { const r = await workerFetch("/orders/list?limit=200"); res.json(await r.json()); }
  catch (e) { res.status(502).json({ error: "Failed", detail: e.message }); }
});
app.get("/orders/:id", requireAdmin, async (req, res) => {
  try {
    const r = await workerFetch(`/orders/get/${encodeURIComponent(req.params.id)}`);
    if (r.status === 404) return res.status(404).json({ error: "Not found" });
    res.json(await r.json());
  } catch (e) { res.status(502).json({ error: "Failed", detail: e.message }); }
});
app.get("/services", requireAdmin, async (req, res) => {
  try { const r = await workerFetch("/services/list?limit=200"); res.json(await r.json()); }
  catch (e) { res.status(502).json({ error: "Failed", detail: e.message }); }
});
app.get("/services/:id", requireAdmin, async (req, res) => {
  try {
    const r = await workerFetch(`/services/get/${encodeURIComponent(req.params.id)}`);
    if (r.status === 404) return res.status(404).json({ error: "Not found" });
    res.json(await r.json());
  } catch (e) { res.status(502).json({ error: "Failed", detail: e.message }); }
});

// =============================================================================
// Payment endpoints — HARDENED
// =============================================================================
function generateOrderId() {
  const buf = crypto.randomBytes(6).toString("hex").toUpperCase();
  return `ORD-${Date.now().toString(36).toUpperCase()}-${buf}`;
}

app.post("/create-payment", paymentLimiter, async (req, res) => {
  const b = safeClone(req.body);

  // ----- Bound + sanitize amount -----
  const amount = Number(b.amount);
  if (!Number.isFinite(amount) || amount < MIN_AMOUNT_LKR || amount > MAX_AMOUNT_LKR) {
    return res.status(400).json({ error: `Amount must be between LKR ${MIN_AMOUNT_LKR} and LKR ${MAX_AMOUNT_LKR}` });
  }

  // ----- Validate customer fields -----
  const first_name = String(b.first_name || "").slice(0, 60).trim();
  const last_name  = String(b.last_name  || "").slice(0, 60).trim();
  const email      = String(b.email      || "").slice(0, 160).trim();
  const phone      = String(b.phone      || "").slice(0, 30).trim();
  if (!first_name || !last_name) return res.status(400).json({ error: "Name required" });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "Valid email required" });
  if (phone.length < 7) return res.status(400).json({ error: "Valid phone required" });

  // ----- Sanitize items[] -----
  const product_name = String(b.product_name || "").slice(0, MAX_ITEM_NAME);
  const qty = Math.max(1, Math.min(100, Number(b.qty) || 1));
  let items = [];
  if (Array.isArray(b.items)) {
    if (b.items.length > MAX_ITEMS) return res.status(400).json({ error: "Too many items" });
    items = b.items.map(it => ({
      name: String(it?.name || "").slice(0, MAX_ITEM_NAME),
      quantity: Math.max(1, Math.min(100, Number(it?.quantity || it?.qty) || 1))
    })).filter(it => it.name.length > 0);
  }
  const coupon_code = b.coupon_code ? String(b.coupon_code).slice(0, 50) : null;

  // ----- Server-generated order_id (NEVER trust client) -----
  const order_id = generateOrderId();

  // ----- Refuse if (extremely unlikely) collision -----
  if (await getOrderFromKV(order_id)) {
    return res.status(503).json({ error: "Order ID collision, retry" });
  }

  await saveOrderToKV({
    ts: Date.now(), order_id, amount, product_name, qty, items, coupon_code,
    customer: { first_name, last_name, email, phone },
    status: "Pending"
  });
  console.log(`[order] ${order_id} | ${product_name || items.length + " items"} | LKR ${amount}${coupon_code ? ` | coupon ${coupon_code}` : ""}`);

  const payload = {
    merchant_id: DIRECTPAY_MERCHANT_ID, order_id, amount,
    currency: "LKR", type: "ONE_TIME",
    first_name, last_name, email, phone,
    response_url: "https://www.api.redtrex.store/callback"
  };
  const payloadString = JSON.stringify(payload);
  const dataString = Buffer.from(payloadString).toString("base64");
  const signature = crypto.createHmac("sha256", DIRECTPAY_SECRET).update(dataString).digest("hex");
  res.json({ order_id, dataString, signature });
});

app.post("/callback", async (req, res) => {
  console.log("DirectPay callback received");
  const receivedSignature = req.headers["authorization"]?.replace("Bearer ", "");
  const generatedSignature = crypto.createHmac("sha256", DIRECTPAY_SECRET).update(JSON.stringify(req.body)).digest("hex");
  if (!receivedSignature || !safeEqual(receivedSignature, generatedSignature)) {
    return res.status(403).send("Invalid signature");
  }

  const b = safeClone(req.body);
  const order_id = String(b.order_id || "");
  const amount = b.amount;
  const status = b.status;
  const normalized = normalizeStatus(status);

  // Merge — never overwrite the customer record we already stored
  const existing = await getOrderFromKV(order_id);
  if (!existing) {
    console.warn(`[callback] order ${order_id} not found — ignoring`);
    return res.status(404).send("Order not found");
  }
  await saveOrderToKV({
    ...existing,
    order_id,
    status: normalized,
    paid_amount: amount,
    paid_at: Date.now()
  });
  console.log(`[callback] ${order_id} | ${status} → ${normalized} | LKR ${amount}`);

  res.redirect(`https://www.redtrex.store/payment-success?order_id=${encodeURIComponent(order_id)}&amount=${encodeURIComponent(amount)}&status=${encodeURIComponent(status)}`);
});

// =============================================================================
// 404 fallback
// =============================================================================
app.use(generalLimiter, (req, res) => {
  res.status(404).send("Not found");
});

// =============================================================================
// Startup guard — fail fast if any required secret is missing
// =============================================================================
const REQUIRED_SECRETS = {
  ADMIN_TOKEN, DIRECTPAY_MERCHANT_ID, DIRECTPAY_SECRET, ORDERS_API_KEY
};
const missing = Object.entries(REQUIRED_SECRETS).filter(([, v]) => !v).map(([k]) => k);
if (missing.length) {
  console.error("FATAL: missing required env vars:", missing.join(", "));
  process.exit(1);
}
if (ADMIN_TOKEN.length < 24) {
  console.error("FATAL: ADMIN_TOKEN must be at least 24 chars (use a long random string).");
  process.exit(1);
}

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log("Server running on port", PORT));
