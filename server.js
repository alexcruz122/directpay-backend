import express from "express";
import crypto from "crypto";
import cors from "cors";

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

const {
  DIRECTPAY_MERCHANT_ID,
  DIRECTPAY_SECRET,
  ADMIN_TOKEN,
  ORDERS_WORKER_URL = "https://redtrex-coupons.projectmmdoffcialdev.workers.dev",
  ORDERS_API_KEY
} = process.env;

const COOKIE_NAME = "rt_admin";
const COOKIE_MAX_AGE_SEC = 60 * 60 * 24 * 7; // 7 days

// ===== Cookie helpers =====
function parseCookies(header = "") {
  const out = {};
  header.split(";").forEach(p => {
    const i = p.indexOf("=");
    if (i > -1) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}

function setAdminCookie(res, value) {
  res.setHeader("Set-Cookie",
    `${COOKIE_NAME}=${encodeURIComponent(value)}; Max-Age=${COOKIE_MAX_AGE_SEC}; Path=/; HttpOnly; Secure; SameSite=Lax`);
}

function clearAdminCookie(res) {
  res.setHeader("Set-Cookie",
    `${COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`);
}

// ===== Worker helpers =====
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
  } catch (e) {
    console.error("[kv-save] error:", e.message);
  }
}

// ===== Auth middleware =====
function requireAdmin(req, res, next) {
  if (!ADMIN_TOKEN) return res.status(503).json({ error: "Admin endpoint disabled" });
  const cookies = parseCookies(req.headers.cookie || "");
  const supplied = cookies[COOKIE_NAME] || req.query.token || req.headers["x-admin-token"];
  if (supplied !== ADMIN_TOKEN) {
    // For browser requests redirect to login; for API return JSON 401
    const wantsHtml = (req.headers.accept || "").includes("text/html");
    if (wantsHtml) return res.redirect("/login");
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

// ===== Public =====
app.get("/", (req, res) => res.send("DirectPay backend running"));

// ===== Login portal =====
app.get("/login", (req, res) => {
  const error = req.query.err === "1" ? `<div class="err">Invalid password. Try again.</div>` : "";
  res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>RedTrex Admin Login</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>
      *{box-sizing:border-box}
      body{font-family:system-ui,Arial;background:linear-gradient(135deg,#0f172a,#1e1b4b);color:#e2e8f0;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
      .card{background:#1e293b;padding:36px 32px;border-radius:14px;width:100%;max-width:380px;box-shadow:0 20px 60px rgba(0,0,0,.4);border:1px solid #334155}
      h1{color:#f87171;margin:0 0 6px;font-size:24px}
      p{color:#94a3b8;margin:0 0 24px;font-size:14px}
      label{display:block;font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px}
      input[type=password]{width:100%;padding:12px 14px;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#fff;font-size:14px;outline:none}
      input[type=password]:focus{border-color:#f87171}
      button{width:100%;margin-top:18px;padding:13px;background:#f87171;color:#0f172a;border:none;border-radius:8px;font-weight:700;font-size:14px;cursor:pointer;text-transform:uppercase;letter-spacing:.5px}
      button:hover{background:#fca5a5}
      .err{background:#7f1d1d;color:#fee2e2;padding:10px 14px;border-radius:6px;margin-bottom:18px;font-size:13px}
      .logo{font-size:32px;margin-bottom:8px}
    </style></head><body>
    <form class="card" method="POST" action="/login">
      <div class="logo">🛒</div>
      <h1>RedTrex Admin</h1>
      <p>Enter your admin password to view orders.</p>
      ${error}
      <label for="pw">Password</label>
      <input id="pw" type="password" name="token" autofocus autocomplete="current-password" required>
      <button type="submit">Sign In</button>
    </form></body></html>`);
});

app.post("/login", (req, res) => {
  const supplied = (req.body.token || "").toString();
  if (!ADMIN_TOKEN || supplied !== ADMIN_TOKEN) {
    return res.redirect("/login?err=1");
  }
  setAdminCookie(res, supplied);
  res.redirect("/admin");
});

app.get("/logout", (req, res) => {
  clearAdminCookie(res);
  res.redirect("/login");
});

// ===== Admin endpoints =====
app.get("/orders", requireAdmin, async (req, res) => {
  try {
    const r = await workerFetch("/orders/list?limit=200");
    res.json(await r.json());
  } catch (e) {
    res.status(502).json({ error: "Failed to fetch orders", detail: e.message });
  }
});

app.get("/orders/:id", requireAdmin, async (req, res) => {
  try {
    const r = await workerFetch(`/orders/get/${encodeURIComponent(req.params.id)}`);
    if (r.status === 404) return res.status(404).json({ error: "Not found" });
    res.json(await r.json());
  } catch (e) {
    res.status(502).json({ error: "Failed to fetch order", detail: e.message });
  }
});

app.get("/admin", requireAdmin, async (req, res) => {
  let all = [];
  let fetchError = null;
  try {
    const r = await workerFetch("/orders/list?limit=500");
    const data = await r.json();
    all = data.orders || [];
  } catch (e) {
    fetchError = e.message;
  }

  const rows = all.map(o => {
    const items = Array.isArray(o.items) && o.items.length > 0
      ? o.items.map(it => `${it.name} ×${it.quantity || it.qty || 1}`).join("<br>")
      : `${o.product_name || "—"} ×${o.qty || 1}`;
    const status = o.status || "pending";
    const statusColor = String(status).toUpperCase().includes("SUCCESS")
      ? "#16a34a" : status === "pending" ? "#f59e0b" : "#ef4444";
    return `
      <tr>
        <td><code>${o.order_id}</code></td>
        <td>${new Date(o.ts).toLocaleString()}</td>
        <td>${items}</td>
        <td>LKR ${o.amount}</td>
        <td>${o.coupon_code || "-"}</td>
        <td>${o.customer?.first_name || ""} ${o.customer?.last_name || ""}<br>
            <small>${o.customer?.email || ""}<br>${o.customer?.phone || ""}</small></td>
        <td style="color:${statusColor};font-weight:700">${status}</td>
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
      small{color:#94a3b8}
    </style></head><body>
    <div class="head">
      <h1>🛒 RedTrex Orders <small style="font-size:14px;font-weight:400;color:#94a3b8">(${all.length} stored)</small></h1>
      <a class="logout" href="/logout">Sign Out</a>
    </div>
    ${fetchError ? `<div class="err">⚠ Could not reach Cloudflare KV: ${fetchError}</div>` : ""}
    <table>
      <thead><tr><th>Order ID</th><th>Time</th><th>Items</th><th>Amount</th><th>Coupon</th><th>Customer</th><th>Status</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="7" style="text-align:center;padding:40px;color:#64748b">No orders yet</td></tr>'}</tbody>
    </table></body></html>`);
});

// ===== Payment endpoints =====
app.post("/create-payment", async (req, res) => {
  const {
    order_id, amount,
    first_name = "", last_name = "", email = "", phone = "",
    product_name = "", qty = 1, items = [], coupon_code = null
  } = req.body;

  if (!order_id || !amount) return res.status(400).json({ error: "Missing order_id or amount" });

  await saveOrderToKV({
    ts: Date.now(), order_id, amount, product_name, qty, items, coupon_code,
    customer: { first_name, last_name, email, phone },
    status: "pending"
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
  res.json({ dataString, signature });
});

app.post("/callback", async (req, res) => {
  console.log("DirectPay callback received");

  const receivedSignature = req.headers["authorization"]?.replace("Bearer ", "");
  const generatedSignature = crypto.createHmac("sha256", DIRECTPAY_SECRET)
    .update(JSON.stringify(req.body)).digest("hex");

  if (receivedSignature !== generatedSignature) return res.status(403).send("Invalid signature");

  const { order_id, amount, status } = req.body;
  await saveOrderToKV({ order_id, status, paid_amount: amount, paid_at: Date.now() });
  console.log(`[callback] ${order_id} | ${status} | LKR ${amount}`);

  res.redirect(`https://www.redtrex.store/payment-success?order_id=${encodeURIComponent(order_id)}&amount=${encodeURIComponent(amount)}&status=${encodeURIComponent(status)}`);
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log("Server running on port", PORT));
