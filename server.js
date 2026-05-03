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
  ORDERS_API_KEY,
  EMAIL_WORKER_URL = "https://resend.projectmmdoffcialdev.workers.dev",
  ORDER_EMAIL_TOKEN
} = process.env;

const COOKIE_NAME = "rt_admin";
const COOKIE_MAX_AGE_SEC = 60 * 60 * 24 * 7;

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
  res.setHeader("Set-Cookie", `${COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`);
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
  } catch (e) { console.error("[kv-save] error:", e.message); }
}
async function updateOrderInKV(payload) {
  const res = await workerFetch("/orders/update", { method: "POST", body: JSON.stringify(payload) });
  if (!res.ok) {
    const txt = await res.text();
    throw new Error(`Worker update failed (${res.status}): ${txt}`);
  }
  return res.json();
}

// ===== Auth middleware =====
function requireAdmin(req, res, next) {
  if (!ADMIN_TOKEN) return res.status(503).json({ error: "Admin endpoint disabled" });
  const cookies = parseCookies(req.headers.cookie || "");
  const supplied = cookies[COOKIE_NAME] || req.query.token || req.headers["x-admin-token"];
  if (supplied !== ADMIN_TOKEN) {
    const wantsHtml = (req.headers.accept || "").includes("text/html");
    if (wantsHtml) return res.redirect("/login");
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

// ===== Helpers =====
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

// ===== Public root =====
app.get("/", (req, res) => res.send("DirectPay backend running"));

// ===== Login portal =====
app.get("/login", (req, res) => {
  const error = req.query.err === "1" ? `<div class="err">Invalid password. Try again.</div>` : "";
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
app.post("/login", (req, res) => {
  const supplied = (req.body.token || "").toString();
  if (!ADMIN_TOKEN || supplied !== ADMIN_TOKEN) return res.redirect("/login?err=1");
  setAdminCookie(res, supplied);
  res.redirect("/admin");
});
app.get("/logout", (req, res) => { clearAdminCookie(res); res.redirect("/login"); });

// ===== Admin: list orders =====
app.get("/admin", requireAdmin, async (req, res) => {
  let all = [], fetchError = null;
  try {
    const r = await workerFetch("/orders/list?limit=500");
    const data = await r.json();
    all = data.orders || [];
  } catch (e) { fetchError = e.message; }

  const rows = all.map(o => {
    const items = Array.isArray(o.items) && o.items.length > 0
      ? o.items.map(it => `${it.name} ×${it.quantity || it.qty || 1}`).join("<br>")
      : `${o.product_name || "—"} ×${o.qty || 1}`;
    return `
      <tr>
        <td><a href="/admin/order/${encodeURIComponent(o.order_id)}" style="color:#f87171;text-decoration:none"><code>${o.order_id}</code></a></td>
        <td>${new Date(o.ts).toLocaleString()}</td>
        <td>${items}</td>
        <td>LKR ${o.amount}</td>
        <td>${o.coupon_code || "-"}</td>
        <td>${o.customer?.first_name || ""} ${o.customer?.last_name || ""}<br>
            <small style="color:#94a3b8">${o.customer?.email || ""}<br>${o.customer?.phone || ""}</small></td>
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
    <div class="head">
      <h1>🛒 RedTrex Orders <small style="font-size:14px;font-weight:400;color:#94a3b8">(${all.length} stored)</small></h1>
      <div style="display:flex;gap:8px">
        <form method="POST" action="/admin/seed-test" style="margin:0">
          <button type="submit" style="background:#16a34a;color:#fff;padding:8px 14px;border:none;border-radius:6px;font-size:13px;font-weight:700;cursor:pointer">+ Create Test Order</button>
        </form>
        <a class="logout" href="/logout">Sign Out</a>
      </div>
    </div>
    ${fetchError ? `<div class="err">⚠ Could not reach Cloudflare KV: ${fetchError}</div>` : ""}
    <table>
      <thead><tr><th>Order ID</th><th>Time</th><th>Items</th><th>Amount</th><th>Coupon</th><th>Customer</th><th>Status</th><th></th></tr></thead>
      <tbody>${rows || '<tr><td colspan="8" style="text-align:center;padding:40px;color:#64748b">No orders yet</td></tr>'}</tbody>
    </table></body></html>`);
});

// ===== Admin: create test order =====
app.post("/admin/seed-test", requireAdmin, async (req, res) => {
  const rand = Math.random().toString(36).slice(2, 7).toUpperCase();
  const order_id = `ORD-TEST-${rand}`;
  const testOrder = {
    ts: Date.now(),
    order_id,
    amount: 4500,
    items: [
      { name: "Windows 11 Pro (TEST)", quantity: 1 },
      { name: "EaseUS Data Recovery (TEST)", quantity: 1 }
    ],
    coupon_code: "TESTCOUPON10",
    customer: {
      first_name: "Test",
      last_name: "Customer",
      email: "test@redtrex.com",
      phone: "+94712622012"
    },
    status: "Pending"
  };
  await saveOrderToKV(testOrder);
  console.log(`[seed-test] created ${order_id}`);
  res.redirect(`/admin/order/${encodeURIComponent(order_id)}?saved=1`);
});

// ===== Admin: single order edit page =====
app.get("/admin/order/:id", requireAdmin, async (req, res) => {
  let order = null, error = null;
  try {
    const r = await workerFetch(`/orders/get/${encodeURIComponent(req.params.id)}`);
    if (r.status === 404) {
      return res.status(404).send(`<p style="font-family:system-ui;padding:30px;color:#fff;background:#0f172a">Order not found. <a href="/admin" style="color:#f87171">← Back</a></p>`);
    }
    order = await r.json();
  } catch (e) { error = e.message; }

  if (!order) return res.send(`<p style="color:red;font-family:system-ui">Error: ${error}</p>`);

  const success = req.query.saved === "1" ? `<div class="ok">✓ Order updated successfully.</div>` : "";
  const emailed = req.query.emailed === "1" ? `<div class="ok" style="background:rgba(99,102,241,.15);color:#a5b4fc;border-color:rgba(99,102,241,.3)">📧 Customer notified by email.</div>` : "";
  const items = Array.isArray(order.items) && order.items.length > 0
    ? order.items
    : [{ name: order.product_name || "Item", quantity: order.qty || 1 }];
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
      select,textarea{width:100%;padding:10px 12px;background:#0f172a;border:1px solid #334155;border-radius:6px;color:#fff;font-size:14px;font-family:inherit;outline:none}
      textarea{min-height:120px;font-family:'DM Mono',monospace,Courier;resize:vertical}
      select:focus,textarea:focus{border-color:#f87171}
      .btn{display:inline-block;padding:11px 22px;background:#dc2626;color:#fff;border:none;border-radius:6px;font-weight:700;font-size:14px;cursor:pointer;text-transform:uppercase;letter-spacing:.5px}
      .btn:hover{background:#b91c1c}
      .ok{background:rgba(22,163,74,.15);color:#4ade80;border:1px solid rgba(22,163,74,.3);padding:10px 14px;border-radius:6px;margin-bottom:14px}
      small{color:#64748b;font-size:12px}
    </style></head><body>
    <a class="back" href="/admin">← Back to all orders</a>
    <h1>Manage Order: <code>${order.order_id}</code></h1>
    ${success}${emailed}
    <div class="card">
      <div class="row"><span>Status</span><span>${statusBadgeHtml(order.status)}</span></div>
      <div class="row"><span>Placed</span><span>${new Date(order.ts).toLocaleString()}</span></div>
      ${order.paid_at ? `<div class="row"><span>Paid at</span><span>${new Date(order.paid_at).toLocaleString()}</span></div>` : ""}
      <div class="row"><span>Amount</span><span><strong>LKR ${order.amount}</strong></span></div>
      ${order.coupon_code ? `<div class="row"><span>Coupon</span><span>${order.coupon_code}</span></div>` : ""}
      <div class="row"><span>Customer</span><span>${order.customer?.first_name || ""} ${order.customer?.last_name || ""}</span></div>
      <div class="row"><span>Email</span><span>${order.customer?.email || "—"}</span></div>
      <div class="row"><span>Phone</span><span>${order.customer?.phone || "—"}</span></div>
    </div>

    <div class="card">
      <strong>Items</strong>
      <div class="row items" style="margin-top:8px">
        ${items.map(it => `<div class="item"><span>${it.name}</span><span>×${it.quantity || it.qty || 1}</span></div>`).join("")}
      </div>
    </div>

    <form class="card" method="POST" action="/admin/order/${encodeURIComponent(order.order_id)}">
      <strong style="font-size:16px">Update Order</strong>

      <label for="status">Status</label>
      <select name="status" id="status">
        <option value="Pending"   ${order.status === "Pending"   ? "selected" : ""}>Pending (paid, awaiting fulfillment)</option>
        <option value="Completed" ${order.status === "Completed" ? "selected" : ""}>Completed (keys delivered)</option>
        <option value="Cancelled" ${order.status === "Cancelled" ? "selected" : ""}>Cancelled</option>
        <option value="Refunded"  ${order.status === "Refunded"  ? "selected" : ""}>Refunded</option>
      </select>

      <label for="product_keys">Product Keys <small>(one per line — visible to customer when status is Completed)</small></label>
      <textarea name="product_keys" id="product_keys" placeholder="XXXXX-XXXXX-XXXXX-XXXXX-XXXXX">${keysText}</textarea>

      <p style="margin:12px 0 0;font-size:13px;color:#94a3b8">
        💡 Setting status to <strong>Completed</strong> will automatically email the customer their keys.
      </p>

      <div style="margin-top:16px">
        <button class="btn" type="submit">Save Changes</button>
      </div>
    </form>
  </body></html>`);
});

// Save order updates from admin (auto-emails customer when status flips to Completed)
app.post("/admin/order/:id", requireAdmin, async (req, res) => {
  const order_id = req.params.id;
  const status = (req.body.status || "").toString();
  const keysRaw = (req.body.product_keys || "").toString();
  const product_keys = keysRaw.split(/\r?\n/).map(s => s.trim()).filter(Boolean);

  try {
    // Fetch the previous order so we can detect a transition into Completed
    let previous = null;
    try {
      const r = await workerFetch(`/orders/get/${encodeURIComponent(order_id)}`);
      if (r.ok) previous = await r.json();
    } catch (_) {}

    await updateOrderInKV({ order_id, status, product_keys });

    // Auto-email customer ONLY when status moves into "Completed" with keys present
    let emailed = false;
    const becameCompleted = status === "Completed" && (!previous || previous.status !== "Completed");
    if (becameCompleted && product_keys.length > 0 && previous?.customer?.email && ORDER_EMAIL_TOKEN) {
      try {
        const emailRes = await fetch(`${EMAIL_WORKER_URL}/send-order-email`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${ORDER_EMAIL_TOKEN}`
          },
          body: JSON.stringify({
            to: previous.customer.email,
            customer_name: `${previous.customer.first_name || ""} ${previous.customer.last_name || ""}`.trim() || "Customer",
            order_id,
            items: previous.items || [],
            product_keys,
            amount: previous.amount
          })
        });
        if (!emailRes.ok) {
          console.error(`[email] failed (${emailRes.status}):`, await emailRes.text());
        } else {
          console.log(`[email] sent to ${previous.customer.email} for ${order_id}`);
          emailed = true;
        }
      } catch (e) {
        console.error("[email] error:", e.message);
      }
    }

    res.redirect(`/admin/order/${encodeURIComponent(order_id)}?saved=1${emailed ? "&emailed=1" : ""}`);
  } catch (e) {
    res.status(500).send(`<p style="color:red;font-family:system-ui;padding:24px">Update failed: ${e.message} <a href="/admin/order/${encodeURIComponent(order_id)}">← Try again</a></p>`);
  }
});

// ===== JSON endpoints =====
app.get("/orders", requireAdmin, async (req, res) => {
  try {
    const r = await workerFetch("/orders/list?limit=200");
    res.json(await r.json());
  } catch (e) { res.status(502).json({ error: "Failed", detail: e.message }); }
});
app.get("/orders/:id", requireAdmin, async (req, res) => {
  try {
    const r = await workerFetch(`/orders/get/${encodeURIComponent(req.params.id)}`);
    if (r.status === 404) return res.status(404).json({ error: "Not found" });
    res.json(await r.json());
  } catch (e) { res.status(502).json({ error: "Failed", detail: e.message }); }
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
  res.json({ dataString, signature });
});

app.post("/callback", async (req, res) => {
  console.log("DirectPay callback received");
  const receivedSignature = req.headers["authorization"]?.replace("Bearer ", "");
  const generatedSignature = crypto.createHmac("sha256", DIRECTPAY_SECRET).update(JSON.stringify(req.body)).digest("hex");
  if (receivedSignature !== generatedSignature) return res.status(403).send("Invalid signature");

  const { order_id, amount, status } = req.body;
  const normalized = normalizeStatus(status);
  await saveOrderToKV({ order_id, status: normalized, paid_amount: amount, paid_at: Date.now() });
  console.log(`[callback] ${order_id} | ${status} → ${normalized} | LKR ${amount}`);

  res.redirect(`https://www.redtrex.store/payment-success?order_id=${encodeURIComponent(order_id)}&amount=${encodeURIComponent(amount)}&status=${encodeURIComponent(status)}`);
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log("Server running on port", PORT));
