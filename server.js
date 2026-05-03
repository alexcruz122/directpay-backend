import express from "express";
import crypto from "crypto";
import cors from "cors";

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

const {
  DIRECTPAY_MERCHANT_ID,
  DIRECTPAY_SECRET
} = process.env;

app.get("/", (req, res) => {
  res.send("DirectPay backend running");
});

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
    items // optional: array of { name, quantity, price }
  } = req.body;

  if (!order_id || !amount) {
    return res.status(400).json({ error: "Missing order_id or amount" });
  }

  // Build a human-readable description + structured line items for DirectPay
  let description;
  let itemsArray;

  if (Array.isArray(items) && items.length > 0) {
    itemsArray = items.map(it => ({
      name: String(it.name || "Item").slice(0, 100),
      quantity: Number(it.quantity || it.qty || 1),
      price: Number(it.price || it.unitPrice || 0)
    }));
    description = itemsArray
      .map(it => `${it.name} x${it.quantity}`)
      .join(", ")
      .slice(0, 250);
  } else {
    itemsArray = [{
      name: String(product_name || "RedTrex Order").slice(0, 100),
      quantity: Number(qty) || 1,
      price: Number(amount)
    }];
    description = `${itemsArray[0].name} x${itemsArray[0].quantity}`;
  }

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
    description,                   // shown in DirectPay dashboard
    product_description: description, // alternate key some DirectPay accounts use
    items: itemsArray,             // structured line items
    response_url: "https://www.api.redtrex.store/callback"
  };

  const payloadString = JSON.stringify(payload);

  const dataString = Buffer
    .from(payloadString)
    .toString("base64");

  const signature = crypto
    .createHmac("sha256", DIRECTPAY_SECRET)
    .update(dataString)
    .digest("hex");

  res.json({
    dataString,
    signature
  });

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

  const redirectUrl =
    `https://www.redtrex.store/payment-success?order_id=${encodeURIComponent(order_id)}&amount=${encodeURIComponent(amount)}&status=${encodeURIComponent(status)}`;

  res.redirect(redirectUrl);

});

const PORT = process.env.PORT || 10000;

app.listen(PORT, () => {
  console.log("Server running on port", PORT);
});
