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
  ADMIN_TOKEN  // any random secret string — required to view /orders
} = process.env;

// In-memory log of every order (keyed by order_id).
// Note: resets when Render restarts/redeploys. For permanent storage,
// upgrade to Render Postgres later.
const orderLog = new Map();

// Tiny middleware: require ?token=<ADMIN_TOKEN> on admin endpoints
function requireAdmin(req, res, next) {
  if (!ADMIN_TOKEN) {
    return res.status(503).json({ error: "Admin endpoint disabled (set ADMIN_TOKEN env var)" });
  }
  const supplied = req.query.token || req.headers["x-admin-token"];
  if (supplied !== ADMIN_TOKEN) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

app.get("/", (req, res) => {
  res.send("DirectPay backend running");
});

// ===== Admin endpoints (require ?token=YOUR_ADMIN_TOKEN) =====

// Latest 100 orders, newest first
app.get("/orders", requireAdmin, (req, res) => {
  const all = Array.from(orderLog.values())
    .sort((a, b) => b.ts - a.ts)
    .slice(0, 100);
  res.json({ count: all.length, orders: all });
});

// Single order lookup by order_id
app.get("/orders/:id", requireAdmin, (req, res) => {
  const entry = orderLog.get(req.params.id);
  if (!entry) return res.status(404).json({ error: "Not found" });
  res.json(entry);
});

// Quick HTML view for browser convenience: /admin?token=YOUR_TOKEN
app.get("/admin", requireAdmin, (req, res) => {
  const all = Array.from(orderLog.values()).sort((a, b) => b.ts - a.ts);
  const rows = all.map(o => {
    const items = Array.isArray(o.items) && o.items.length > 0
      ? o.items.map(it => `${it.name} x${it.quantity || it.qty || 1}`).join("<br>")
      : `${o.product_name || ""} x${o.qty || 1}`;
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
        <td>${o.customer?.email || ""}<br><small>${o.customer?.phone || ""}</small></td>
        <td style="color:${statusColor};font-weight:700">${status}</td>
      </tr>`;
  }).join("");
  res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>RedTrex Orders</title>
    <style>
      body{font-family:system-ui,Arial;background:#0f172a;color:#e2e8f0;padding:24px;margin:0}
      h1{color:#f87171;margin:0 0 16px}
      table{width:100%;border-collapse:collapse;background:#1e293b;border-radius:8px;overflow:hidden}
      th,td{padding:10px 12px;text-align:left;border-bottom:1px solid #334155;font-size:13px;vertical-align:top}
      th{background:#0f172a;color:#94a3b8;text-transform:uppercase;font-size:11px}
      tr:hover td{background:#283548}
      code{background:#0f172a;padding:2px 6px;border-radius:4px;font-size:11px}
    </style></head><body>
    <h1>🛒 RedTrex Orders <small style="color:#94a3b8;font-size:14px;font-weight:400">(${all.length} total)</small></h1>
    <table>
      <thead><tr><th>Order ID</th><th>Time</th><th>Items</th><th>Amount</th><th>Coupon</th><th>Customer</th><th>Status</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="7" style="text-align:center;padding:40px;color:#64748b">No orders yet</td></tr>'}</tbody>
    </table></body></html>`);
});

// ===== Payment endpoints =====

app.post("/create-payment", (req, res) => {
  const {
    order_id,
    amount,
    first_name = "",
    last_name = "",
    email = "",
    phone = "",
    product_name = "",
    qty = 1,
    items = [],
    coupon_code = null
  } = req.body;

  if (!order_id || !amount) {
    return res.status(400).json({ error: "Missing order_id or amount" });
  }

  // Persist the full order context so we can look it up later by order_id.
  // (DirectPay only shows order_id + amount in their dashboard.)
  orderLog.set(order_id, {
    ts: Date.now(),
    order_id,
    amount,
    product_name,
    qty,
    items,
    coupon_code,
    customer: { first_name, last_name, email, phone },
    status: "pending"
  });
  console.log(`[order] ${order_id} | ${product_name} x${qty} | LKR ${amount}${coupon_code ? ` | coupon ${coupon_code}` : ""}`);

  // DirectPay IPG payload (only fields they accept)
  const payload = {
    merchant_id: DIRECTPAY_MERCHANT_ID,
    order_id,
    amount,
    currency: "LKR",
    type: "ONE_TIME",
    first_name,
    last_name,
    email,
    phone,
    response_url: "https://www.api.redtrex.store/callback"
  };

  const payloadString = JSON.stringify(payload);
  const dataString = Buffer.from(payloadString).toString("base64");
  const signature = crypto
    .createHmac("sha256", DIRECTPAY_SECRET)
    .update(dataString)
    .digest("hex");

  res.json({ dataString, signature });
});

app.post("/callback", (req, res) => {
  console.log("DirectPay callback received");

  const receivedSignature =
    req.headers["authorization"]?.replace("Bearer ", "");

  const generatedSignature = crypto
    .createHmac("sha256", DIRECTPAY_SECRET)
    .update(JSON.stringify(req.body))
    .digest("hex");

  if (receivedSignature !== generatedSignature) {
    return res.status(403).send("Invalid signature");
  }

  const { order_id, amount, status } = req.body;

  // Update the log with the final payment status
  const entry = orderLog.get(order_id);
  if (entry) {
    entry.status = status;
    entry.paid_amount = amount;
    entry.paid_at = Date.now();
    orderLog.set(order_id, entry);
  }
  console.log(`[callback] ${order_id} | ${status} | LKR ${amount}`);

  const redirectUrl =
    `https://www.redtrex.store/payment-success?order_id=${encodeURIComponent(order_id)}&amount=${encodeURIComponent(amount)}&status=${encodeURIComponent(status)}`;

  res.redirect(redirectUrl);
});

const PORT = process.env.PORT || 10000;

app.listen(PORT, () => {
  console.log("Server running on port", PORT);
});
