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
    phone = ""
  } = req.body;

  if (!order_id || !amount) {
    return res.status(400).json({ error: "Missing order_id or amount" });
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
