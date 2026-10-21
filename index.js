/* RP Agro Food — Express + MongoDB + Razorpay
 * Node 24.x. All customer UI is embedded in this file; /admin serves admin.js.
 * Required env: MONGODB_URI, SESSION_SECRET, ADMIN_EMAIL, ADMIN_PASSWORD_HASH.
 */
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const Razorpay = require("razorpay");
const adminHtml = require("./admin");

const app = express();
const PORT = process.env.PORT || 3000;
const isProd = process.env.NODE_ENV === "production";
const COOKIE = "rpaf_session";
const TAX_RATE = Math.max(0, Math.min(0.28, Number(process.env.TAX_RATE || 0)));
const SHIPPING = Math.max(0, Number(process.env.DEFAULT_SHIPPING_CHARGE || 60));
const COD_ENABLED = process.env.CASH_ON_DELIVERY_ENABLED === "true";
const RAZORPAY_ENABLED = process.env.RAZORPAY_ENABLED !== "false";
const razorpay = process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET
  ? new Razorpay({ key_id: process.env.RAZORPAY_KEY_ID, key_secret: process.env.RAZORPAY_KEY_SECRET }) : null;

app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cookieParser());
app.use(express.json({
  limit: "200kb",
  verify: (req, res, buf) => { if (req.originalUrl === "/api/payments/razorpay/webhook") req.rawBody = Buffer.from(buf); }
}));
app.use(express.urlencoded({ extended: false, limit: "50kb" }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: "draft-8", legacyHeaders: false }));
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 12, standardHeaders: "draft-8", legacyHeaders: false });
const enquiryLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 8, standardHeaders: "draft-8", legacyHeaders: false });

const ProductSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 120 },
  slug: { type: String, required: true, unique: true, index: true },
  sku: { type: String, required: true, unique: true, uppercase: true, trim: true },
  description: { type: String, default: "", maxlength: 3000 },
  category: { type: String, required: true, index: true },
  images: [{ type: String, maxlength: 1000 }],
  variants: [{ label: String, price: { type: Number, min: 0 }, stock: { type: Number, min: 0 } }],
  price: { type: Number, required: true, min: 0 },
  unit: { type: String, default: "1 kg", maxlength: 50 },
  inventory: { type: Number, default: 0, min: 0 },
  lowStockThreshold: { type: Number, default: 5, min: 0 },
  weight: { type: Number, default: 1, min: 0 },
  ingredients: { type: String, default: "" },
  storageInstructions: { type: String, default: "" },
  allergens: { type: String, default: "" },
  isFeatured: { type: Boolean, default: false },
  isActive: { type: Boolean, default: true },
}, { timestamps: true });
ProductSchema.index({ name: "text", sku: "text", description: "text" });
const Product = mongoose.model("Product", ProductSchema);

const Category = mongoose.model("Category", new mongoose.Schema({
  name: { type: String, required: true, trim: true, unique: true },
  slug: { type: String, required: true, unique: true },
  description: { type: String, default: "" }, image: { type: String, default: "" },
  isActive: { type: Boolean, default: true }, sortOrder: { type: Number, default: 0 }
}, { timestamps: true }));

const User = mongoose.model("User", new mongoose.Schema({
  name: { type: String, required: true, maxlength: 120 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  phone: { type: String, default: "", maxlength: 30 },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ["customer", "admin"], default: "customer" },
  addresses: [{ fullName: String, phone: String, line1: String, line2: String, city: String, state: String, pin: String }],
  isActive: { type: Boolean, default: true }
}, { timestamps: true }));

const Order = mongoose.model("Order", new mongoose.Schema({
  orderNumber: { type: String, unique: true, index: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null, index: true },
  customerDetails: { name: String, email: String, phone: String, address: String, city: String, state: String, pin: String, instructions: String },
  items: [{ productId: mongoose.Schema.Types.ObjectId, name: String, sku: String, unit: String, quantity: Number, unitPrice: Number, lineTotal: Number }],
  subtotal: Number, discount: { type: Number, default: 0 }, shipping: Number, tax: Number, total: Number,
  currency: { type: String, default: "INR" },
  paymentMethod: { type: String, enum: ["razorpay", "cod"], required: true },
  paymentStatus: { type: String, enum: ["pending", "processing", "paid", "failed", "refund_pending", "refunded"], default: "pending", index: true },
  orderStatus: { type: String, enum: ["Pending Payment", "Confirmed", "Processing", "Packed", "Shipped", "Out for Delivery", "Delivered", "Cancelled", "Refund Pending", "Refunded"], default: "Pending Payment", index: true },
  razorpayOrderId: String, razorpayPaymentId: String, trackingNumber: String, trackingUrl: String, adminNotes: String,
  statusHistory: [{ status: String, note: String, at: { type: Date, default: Date.now } }],
  inventoryCommitted: { type: Boolean, default: false }
}, { timestamps: true }));

const Payment = mongoose.model("Payment", new mongoose.Schema({
  orderId: { type: mongoose.Schema.Types.ObjectId, ref: "Order", required: true, index: true },
  provider: { type: String, default: "razorpay" }, providerOrderId: { type: String, index: true },
  providerPaymentId: { type: String, unique: true, sparse: true }, amount: Number, currency: String,
  status: String, signatureVerified: { type: Boolean, default: false }, webhookEventIds: { type: [String], default: [] }
}, { timestamps: true }));

const Enquiry = mongoose.model("Enquiry", new mongoose.Schema({
  name: { type: String, required: true, maxlength: 120 }, email: { type: String, required: true, maxlength: 254 },
  phone: { type: String, required: true, maxlength: 30 }, enquiryType: { type: String, default: "General enquiry" },
  productInterest: { type: String, default: "", maxlength: 200 }, quantity: { type: String, default: "", maxlength: 100 },
  businessName: { type: String, default: "", maxlength: 200 }, businessType: { type: String, default: "", maxlength: 100 },
  location: { type: String, default: "", maxlength: 200 }, packaging: { type: String, default: "", maxlength: 200 },
  message: { type: String, required: true, maxlength: 3000 }, status: { type: String, enum: ["New", "In Progress", "Responded", "Closed"], default: "New" },
  internalNotes: { type: String, default: "", maxlength: 2000 }
}, { timestamps: true }));

const Coupon = mongoose.model("Coupon", new mongoose.Schema({
  code: { type: String, required: true, unique: true, uppercase: true, trim: true },
  discountType: { type: String, enum: ["percentage", "fixed"], required: true },
  discountValue: { type: Number, min: 0, required: true }, maximumDiscount: Number, minimumOrderValue: { type: Number, default: 0 },
  usageLimit: Number, usedCount: { type: Number, default: 0 }, perCustomerLimit: { type: Number, default: 1 },
  startDate: Date, expiryDate: Date, isActive: { type: Boolean, default: true }
}, { timestamps: true }));

const InventoryMovement = mongoose.model("InventoryMovement", new mongoose.Schema({
  productId: { type: mongoose.Schema.Types.ObjectId, ref: "Product", required: true },
  quantityChange: Number, reason: { type: String, required: true }, orderId: mongoose.Schema.Types.ObjectId,
  adminId: mongoose.Schema.Types.ObjectId
}, { timestamps: true }));

let dbPromise;
async function connectDB() {
  if (mongoose.connection.readyState === 1) return;
  if (!process.env.MONGODB_URI) throw new Error("MONGODB_URI is not configured");
  if (!dbPromise) dbPromise = mongoose.connect(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 8000, maxPoolSize: 8 }).catch(e => { dbPromise = null; throw e; });
  await dbPromise;
}
function fail(res, status, message) { return res.status(status).json({ ok: false, error: message }); }
function clean(v, max = 500) { return String(v ?? "").trim().slice(0, max); }
function slugify(v) { return clean(v, 120).toLowerCase().normalize("NFKD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, ""); }
function validEmail(v) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v); }
function rupees(n) { return Math.round((Number(n) + Number.EPSILON) * 100) / 100; }
function paise(n) { return Math.round(rupees(n) * 100); }
function safeUser(u) { return { id: String(u._id), name: u.name, email: u.email, phone: u.phone, role: u.role, addresses: u.addresses || [] }; }
function sign(value) {
  if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) throw new Error("SESSION_SECRET must be at least 32 characters");
  const payload = Buffer.from(JSON.stringify({ ...value, exp: Date.now() + 7 * 86400000 })).toString("base64url");
  return payload + "." + crypto.createHmac("sha256", process.env.SESSION_SECRET).update(payload).digest("base64url");
}
function readToken(token) {
  if (!token || !process.env.SESSION_SECRET) return null;
  const [payload, sig] = token.split(".");
  if (!payload || !sig) return null;
  const expected = crypto.createHmac("sha256", process.env.SESSION_SECRET).update(payload).digest();
  let got; try { got = Buffer.from(sig, "base64url"); } catch { return null; }
  if (got.length !== expected.length || !crypto.timingSafeEqual(got, expected)) return null;
  try { const d = JSON.parse(Buffer.from(payload, "base64url").toString()); return d.exp > Date.now() ? d : null; } catch { return null; }
}
function setCookie(res, value) {
  res.cookie(COOKIE, value, { httpOnly: true, secure: isProd, sameSite: "lax", path: "/", maxAge: 7 * 86400000 });
}
function requireAuth(req, res, next) {
  const token = readToken(req.cookies[COOKIE]);
  if (!token || !token.sub) return fail(res, 401, "Please sign in to continue.");
  req.auth = token; next();
}
function requireAdmin(req, res, next) {
  const token = readToken(req.cookies[COOKIE]);
  if (!token || token.role !== "admin") return fail(res, 401, "Administrator authentication required.");
  req.auth = token; next();
}
function sameOrigin(req, res, next) {
  const origin = req.get("origin");
  const allowed = process.env.ALLOWED_ORIGIN || process.env.SITE_URL;
  if (origin && allowed && origin !== allowed) return fail(res, 403, "Origin not allowed.");
  next();
}
app.use("/api", sameOrigin);
app.get("/api/health", async (req, res) => {
  res.json({ ok: true, service: "RP Agro Food", database: mongoose.connection.readyState === 1 ? "connected" : "not-connected", paymentsConfigured: Boolean(razorpay && RAZORPAY_ENABLED) });
});
app.get("/admin", (req, res) => res.type("html").send(adminHtml));
app.get("/admin.js", (req, res) => res.type("application/javascript").send(adminHtml));
app.get("/api/config", (req, res) => res.json({ ok: true, razorpayKeyId: razorpay && RAZORPAY_ENABLED ? process.env.RAZORPAY_KEY_ID : null, supportEmail: process.env.SUPPORT_EMAIL || "hello@rpagrofood.example" }));

app.get("/api/products/featured", async (req, res, next) => { req.query.featured = "true"; next(); });
app.get("/api/products", async (req, res) => {
  try {
    await connectDB();
    const page = Math.max(1, parseInt(req.query.page, 10) || 1), limit = Math.min(48, Math.max(1, parseInt(req.query.limit, 10) || 12));
    const filter = { isActive: true };
    if (req.query.category) filter.category = clean(req.query.category, 100);
    if (req.query.featured === "true") filter.isFeatured = true;
    if (req.query.available === "true") filter.inventory = { $gt: 0 };
    if (req.query.q) {
      const q = clean(req.query.q, 100).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      filter.$or = [{ name: new RegExp(q, "i") }, { sku: new RegExp(q, "i") }, { description: new RegExp(q, "i") }];
    }
    if (req.query.minPrice || req.query.maxPrice) filter.price = { ...(req.query.minPrice ? { $gte: Math.max(0, Number(req.query.minPrice)) } : {}), ...(req.query.maxPrice ? { $lte: Math.max(0, Number(req.query.maxPrice)) } : {}) };
    const sortMap = { "price-asc": { price: 1 }, "price-desc": { price: -1 }, "name": { name: 1 }, "newest": { createdAt: -1 } };
    const [items, total] = await Promise.all([Product.find(filter).sort(sortMap[req.query.sort] || { isFeatured: -1, createdAt: -1 }).skip((page - 1) * limit).limit(limit).lean(), Product.countDocuments(filter)]);
    res.json({ ok: true, items, page, pages: Math.ceil(total / limit), total });
  } catch (e) { next(e); }
});
app.get("/api/products/:slug", async (req, res, next) => {
  try { await connectDB(); const p = await Product.findOne({ slug: clean(req.params.slug, 150), isActive: true }).lean(); if (!p) return fail(res, 404, "Product not found."); res.json({ ok: true, item: p }); } catch (e) { next(e); }
});
app.get("/api/categories", async (req, res, next) => {
  try { await connectDB(); const items = await Category.find({ isActive: true }).sort({ sortOrder: 1, name: 1 }).lean(); const counts = await Product.aggregate([{ $match: { isActive: true } }, { $group: { _id: "$category", count: { $sum: 1 } } }]); const map = Object.fromEntries(counts.map(c => [c._id, c.count])); res.json({ ok: true, items: items.map(c => ({ ...c, productCount: map[c.name] || 0 })) }); } catch (e) { next(e); }
});
app.get("/api/categories/:slug", async (req, res, next) => {
  try { await connectDB(); const c = await Category.findOne({ slug: clean(req.params.slug, 150), isActive: true }).lean(); if (!c) return fail(res, 404, "Category not found."); res.json({ ok: true, item: c }); } catch (e) { next(e); }
});

app.post("/api/auth/register", authLimiter, async (req, res, next) => {
  try {
    await connectDB(); const name = clean(req.body.name, 120), email = clean(req.body.email, 254).toLowerCase(), phone = clean(req.body.phone, 30), password = String(req.body.password || "");
    if (name.length < 2 || !validEmail(email) || password.length < 10 || password.length > 128) return fail(res, 400, "Enter a name, valid email, and password of 10–128 characters.");
    const passwordHash = await bcrypt.hash(password, 12);
    const user = await User.create({ name, email, phone, passwordHash, role: "customer" });
    setCookie(res, sign({ sub: String(user._id), role: "customer" }));
    res.status(201).json({ ok: true, user: safeUser(user) });
  } catch (e) { if (e.code === 11000) return fail(res, 409, "Unable to create account with those details."); next(e); }
});
app.post("/api/auth/login", authLimiter, async (req, res, next) => {
  try {
    await connectDB(); const email = clean(req.body.email, 254).toLowerCase(), password = String(req.body.password || "");
    const user = await User.findOne({ email, isActive: true });
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) return fail(res, 401, "Email or password is incorrect.");
    setCookie(res, sign({ sub: String(user._id), role: user.role })); res.json({ ok: true, user: safeUser(user) });
  } catch (e) { next(e); }
});
app.post("/api/auth/logout", (req, res) => { res.clearCookie(COOKIE, { httpOnly: true, secure: isProd, sameSite: "lax", path: "/" }); res.json({ ok: true }); });
app.get("/api/auth/me", requireAuth, async (req, res, next) => {
  try { await connectDB(); const u = await User.findById(req.auth.sub); if (!u || !u.isActive) return fail(res, 401, "Please sign in again."); res.json({ ok: true, user: safeUser(u) }); } catch (e) { next(e); }
});
app.post("/api/auth/change-password", requireAuth, authLimiter, async (req, res, next) => {
  try { await connectDB(); const u = await User.findById(req.auth.sub); if (!u || !(await bcrypt.compare(String(req.body.currentPassword || ""), u.passwordHash))) return fail(res, 400, "Current password is incorrect."); const p = String(req.body.newPassword || ""); if (p.length < 10 || p.length > 128) return fail(res, 400, "New password must be 10–128 characters."); u.passwordHash = await bcrypt.hash(p, 12); await u.save(); res.json({ ok: true }); } catch (e) { next(e); }
});
app.get("/api/account/profile", requireAuth, async (req, res, next) => { try { await connectDB(); const u = await User.findById(req.auth.sub); if (!u) return fail(res, 404, "Account not found."); res.json({ ok: true, user: safeUser(u) }); } catch (e) { next(e); } });
app.patch("/api/account/profile", requireAuth, async (req, res, next) => {
  try { await connectDB(); const u = await User.findById(req.auth.sub); if (!u) return fail(res, 404, "Account not found."); if (req.body.name) u.name = clean(req.body.name, 120); if (req.body.phone !== undefined) u.phone = clean(req.body.phone, 30); await u.save(); res.json({ ok: true, user: safeUser(u) }); } catch (e) { next(e); }
});
app.get("/api/account/orders", requireAuth, async (req, res, next) => { try { await connectDB(); const items = await Order.find({ userId: req.auth.sub }).sort({ createdAt: -1 }).limit(50).lean(); res.json({ ok: true, items }); } catch (e) { next(e); } });
app.get("/api/account/orders/:orderNumber", requireAuth, async (req, res, next) => { try { await connectDB(); const o = await Order.findOne({ orderNumber: clean(req.params.orderNumber, 40), userId: req.auth.sub }).lean(); if (!o) return fail(res, 404, "Order not found."); res.json({ ok: true, item: o }); } catch (e) { next(e); } });
app.post("/api/account/addresses", requireAuth, async (req, res, next) => { try { await connectDB(); const u = await User.findById(req.auth.sub); const a = validateAddress(req.body); if (!a) return fail(res, 400, "Please provide a complete delivery address."); u.addresses.push(a); await u.save(); res.status(201).json({ ok: true, addresses: u.addresses }); } catch (e) { next(e); } });
app.patch("/api/account/addresses/:addressId", requireAuth, async (req, res, next) => { try { await connectDB(); const u = await User.findById(req.auth.sub); const a = u.addresses.id(req.params.addressId); if (!a) return fail(res, 404, "Address not found."); const n = validateAddress(req.body); if (!n) return fail(res, 400, "Please provide a complete delivery address."); Object.assign(a, n); await u.save(); res.json({ ok: true, addresses: u.addresses }); } catch (e) { next(e); } });
app.delete("/api/account/addresses/:addressId", requireAuth, async (req, res, next) => { try { await connectDB(); const u = await User.findById(req.auth.sub); const a = u.addresses.id(req.params.addressId); if (!a) return fail(res, 404, "Address not found."); a.deleteOne(); await u.save(); res.json({ ok: true, addresses: u.addresses }); } catch (e) { next(e); } });
function validateAddress(b = {}) {
  const a = { fullName: clean(b.fullName, 120), phone: clean(b.phone, 30), line1: clean(b.line1, 250), line2: clean(b.line2, 250), city: clean(b.city, 100), state: clean(b.state, 100), pin: clean(b.pin, 10) };
  return a.fullName && a.phone && a.line1 && a.city && a.state && /^\d{6}$/.test(a.pin) ? a : null;
}
async function calculateCart(items) {
  if (!Array.isArray(items) || !items.length || items.length > 50) throw Object.assign(new Error("Your cart is empty or invalid."), { status: 400 });
  const merged = new Map();
  for (const row of items) {
    const id = clean(row.productId, 50), qty = Number(row.quantity);
    if (!mongoose.isValidObjectId(id) || !Number.isInteger(qty) || qty < 1 || qty > 50) throw Object.assign(new Error("One or more cart quantities are invalid."), { status: 400 });
    merged.set(id, (merged.get(id) || 0) + qty);
  }
  const products = await Product.find({ _id: { $in: [...merged.keys()] }, isActive: true });
  if (products.length !== merged.size) throw Object.assign(new Error("A product in your cart is no longer available."), { status: 409 });
  const lines = [];
  for (const p of products) {
    const quantity = merged.get(String(p._id));
    if (p.inventory < quantity) throw Object.assign(new Error(`${p.name} has only ${p.inventory} unit(s) available.`), { status: 409 });
    lines.push({ productId: p._id, name: p.name, sku: p.sku, unit: p.unit, quantity, unitPrice: rupees(p.price), lineTotal: rupees(p.price * quantity) });
  }
  const subtotal = rupees(lines.reduce((s, i) => s + i.lineTotal, 0));
  const shipping = subtotal >= Number(process.env.FREE_SHIPPING_THRESHOLD || 1500) ? 0 : SHIPPING;
  const tax = rupees(subtotal * TAX_RATE);
  return { lines, subtotal, discount: 0, shipping, tax, total: rupees(subtotal + shipping + tax) };
}
app.post("/api/checkout/validate", async (req, res, next) => {
  try { await connectDB(); const cart = await calculateCart(req.body.items); res.json({ ok: true, summary: cart, taxRate: TAX_RATE }); } catch (e) { next(e); }
});
app.post("/api/orders", async (req, res, next) => {
  try {
    await connectDB();
    const method = req.body.paymentMethod === "cod" ? "cod" : "razorpay";
    if (method === "cod" && !COD_ENABLED) return fail(res, 400, "Cash on Delivery is not enabled.");
    if (method === "razorpay" && (!razorpay || !RAZORPAY_ENABLED)) return fail(res, 503, "Online payments are not configured. Please contact the store.");
    const customer = req.body.customer || {};
    const details = { name: clean(customer.name, 120), email: clean(customer.email, 254).toLowerCase(), phone: clean(customer.phone, 30), address: clean(customer.address, 250), city: clean(customer.city, 100), state: clean(customer.state, 100), pin: clean(customer.pin, 10), instructions: clean(customer.instructions, 500) };
    if (details.name.length < 2 || !validEmail(details.email) || !details.phone || !details.address || !details.city || !details.state || !/^\d{6}$/.test(details.pin)) return fail(res, 400, "Please complete all required delivery details and a valid six-digit PIN code.");
    const cart = await calculateCart(req.body.items);
    const userId = readToken(req.cookies[COOKIE])?.sub || null;
    const orderNumber = "RPA-" + Date.now().toString(36).toUpperCase() + "-" + crypto.randomBytes(3).toString("hex").toUpperCase();
    const order = await Order.create({ orderNumber, userId, customerDetails: details, items: cart.lines, subtotal: cart.subtotal, discount: cart.discount, shipping: cart.shipping, tax: cart.tax, total: cart.total, paymentMethod: method, paymentStatus: method === "cod" ? "pending" : "processing", orderStatus: method === "cod" ? "Confirmed" : "Pending Payment", statusHistory: [{ status: method === "cod" ? "Confirmed" : "Pending Payment", note: "Order created" }] });
    if (method === "cod") {
      const committed = await reserveInventory(order);
      if (!committed) { await Order.deleteOne({ _id: order._id }); return fail(res, 409, "Stock changed while placing your order. Please refresh your cart."); }
      order.inventoryCommitted = true; await order.save();
      return res.status(201).json({ ok: true, order: publicOrder(order), message: "Order placed. Payment is due on delivery." });
    }
    try {
      const rzOrder = await razorpay.orders.create({ amount: paise(cart.total), currency: "INR", receipt: orderNumber, notes: { orderNumber } });
      order.razorpayOrderId = rzOrder.id; await order.save();
      await Payment.create({ orderId: order._id, providerOrderId: rzOrder.id, amount: paise(cart.total), currency: "INR", status: "created" });
      res.status(201).json({ ok: true, order: publicOrder(order), razorpay: { keyId: process.env.RAZORPAY_KEY_ID, orderId: rzOrder.id, amount: rzOrder.amount, currency: rzOrder.currency } });
    } catch (e) { order.paymentStatus = "failed"; order.orderStatus = "Cancelled"; await order.save(); throw e; }
  } catch (e) { next(e); }
});
function publicOrder(o) { return { orderNumber: o.orderNumber, items: o.items, subtotal: o.subtotal, discount: o.discount, shipping: o.shipping, tax: o.tax, total: o.total, paymentStatus: o.paymentStatus, orderStatus: o.orderStatus, customerDetails: o.customerDetails, createdAt: o.createdAt }; }
async function reserveInventory(order) {
  const done = [];
  try {
    for (const item of order.items) {
      const p = await Product.findOneAndUpdate({ _id: item.productId, isActive: true, inventory: { $gte: item.quantity } }, { $inc: { inventory: -item.quantity } }, { new: true });
      if (!p) throw new Error("stock");
      done.push(item);
      await InventoryMovement.create({ productId: item.productId, quantityChange: -item.quantity, reason: "Order " + order.orderNumber, orderId: order._id });
    }
    return true;
  } catch {
    for (const item of done) await Product.updateOne({ _id: item.productId }, { $inc: { inventory: item.quantity } });
    return false;
  }
}
async function confirmPaid(order, paymentId) {
  const current = await Order.findById(order._id);
  if (!current || current.paymentStatus === "paid") return current;
  if (current.inventoryCommitted) { current.paymentStatus = "paid"; current.orderStatus = "Confirmed"; current.razorpayPaymentId = paymentId; current.statusHistory.push({ status: "Confirmed", note: "Payment verified" }); await current.save(); return current; }
  const committed = await reserveInventory(current);
  if (!committed) { current.paymentStatus = "processing"; current.orderStatus = "Pending Payment"; await current.save(); throw new Error("Payment received but stock reservation needs manual review."); }
  current.inventoryCommitted = true; current.paymentStatus = "paid"; current.orderStatus = "Confirmed"; current.razorpayPaymentId = paymentId; current.statusHistory.push({ status: "Confirmed", note: "Payment verified" }); await current.save();
  await Payment.updateOne({ providerOrderId: current.razorpayOrderId }, { $set: { providerPaymentId: paymentId, status: "paid", signatureVerified: true } });
  return current;
}
app.post("/api/payments/razorpay/verify", async (req, res, next) => {
  try {
    await connectDB();
    if (!razorpay || !process.env.RAZORPAY_KEY_SECRET) return fail(res, 503, "Online payments are not configured.");
    const orderId = clean(req.body.razorpay_order_id, 100), paymentId = clean(req.body.razorpay_payment_id, 100), signature = clean(req.body.razorpay_signature, 200);
    const order = await Order.findOne({ razorpayOrderId: orderId });
    if (!order || !paymentId || !signature) return fail(res, 400, "Payment details are incomplete.");
    const expected = crypto.createHmac("sha256", process.env.RAZORPAY_KEY_SECRET).update(orderId + "|" + paymentId).digest("hex");
    const a = Buffer.from(expected), b = Buffer.from(signature);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return fail(res, 400, "Payment signature could not be verified.");
    const payment = await razorpay.payments.fetch(paymentId);
    if (payment.order_id !== orderId || payment.amount !== paise(order.total) || payment.currency !== "INR" || !["captured", "authorized"].includes(payment.status)) return fail(res, 400, "Payment is not in a valid state.");
    const updated = await confirmPaid(order, paymentId);
    res.json({ ok: true, order: publicOrder(updated) });
  } catch (e) { next(e); }
});
app.post("/api/payments/razorpay/webhook", async (req, res, next) => {
  try {
    await connectDB();
    if (!process.env.RAZORPAY_WEBHOOK_SECRET) return fail(res, 503, "Webhook secret is not configured.");
    const sig = req.get("x-razorpay-signature");
    const expected = crypto.createHmac("sha256", process.env.RAZORPAY_WEBHOOK_SECRET).update(req.rawBody || Buffer.from("")).digest("hex");
    if (!sig || expected.length !== sig.length || !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig))) return fail(res, 400, "Invalid webhook signature.");
    const event = req.body, eventId = clean(req.get("x-razorpay-event-id"), 200);
    const entity = event?.payload?.payment?.entity;
    if (eventId && entity?.order_id) {
      const payment = await Payment.findOne({ providerOrderId: entity.order_id });
      if (payment && payment.webhookEventIds.includes(eventId)) return res.json({ ok: true, duplicate: true });
      if (payment) { payment.webhookEventIds.push(eventId); await payment.save(); }
    }
    if (entity?.order_id && ["payment.captured", "order.paid"].includes(event.event)) {
      const order = await Order.findOne({ razorpayOrderId: entity.order_id });
      if (order && entity.amount === paise(order.total) && entity.currency === "INR") await confirmPaid(order, entity.id);
    } else if (entity?.order_id && event.event === "payment.failed") {
      await Order.updateOne({ razorpayOrderId: entity.order_id, paymentStatus: { $ne: "paid" } }, { $set: { paymentStatus: "failed" } });
      await Payment.updateOne({ providerOrderId: entity.order_id }, { $set: { status: "failed" } });
    }
    res.json({ ok: true });
  } catch (e) { next(e); }
});
app.get("/api/orders/:orderNumber", async (req, res, next) => {
  try { await connectDB(); const token = readToken(req.cookies[COOKIE]); const order = await Order.findOne({ orderNumber: clean(req.params.orderNumber, 50), ...(token?.sub ? { userId: token.sub } : {}) }).lean(); if (!order) return fail(res, 404, "Order not found. Sign in to view your order."); res.json({ ok: true, item: publicOrder(order) }); } catch (e) { next(e); }
});
app.post("/api/orders/:orderNumber/cancel", requireAuth, async (req, res, next) => {
  try { await connectDB(); const o = await Order.findOne({ orderNumber: clean(req.params.orderNumber, 50), userId: req.auth.sub }); if (!o) return fail(res, 404, "Order not found."); if (!["Pending Payment", "Confirmed"].includes(o.orderStatus) || o.paymentStatus === "paid") return fail(res, 409, "This order is no longer eligible for self-service cancellation."); o.orderStatus = "Cancelled"; o.statusHistory.push({ status: "Cancelled", note: "Customer cancellation" }); if (o.inventoryCommitted) { for (const i of o.items) { await Product.updateOne({ _id: i.productId }, { $inc: { inventory: i.quantity } }); await InventoryMovement.create({ productId: i.productId, quantityChange: i.quantity, reason: "Cancellation " + o.orderNumber, orderId: o._id }); } o.inventoryCommitted = false; } await o.save(); res.json({ ok: true, order: publicOrder(o) }); } catch (e) { next(e); }
});

app.post("/api/enquiries", enquiryLimiter, async (req, res, next) => {
  try {
    await connectDB(); const b = req.body || {};
    if (b.website) return res.status(201).json({ ok: true, message: "Thank you. Your enquiry has been received." });
    const name = clean(b.name, 120), email = clean(b.email, 254).toLowerCase(), phone = clean(b.phone, 30), message = clean(b.message, 3000);
    if (name.length < 2 || !validEmail(email) || phone.length < 7 || message.length < 10) return fail(res, 400, "Please enter a valid name, email, phone, and message (at least 10 characters).");
    const item = await Enquiry.create({ name, email, phone, message, enquiryType: clean(b.enquiryType, 100) || "General enquiry", productInterest: clean(b.productInterest, 200), quantity: clean(b.quantity, 100) });
    res.status(201).json({ ok: true, id: item._id, message: "Thank you. Your enquiry has been received." });
  } catch (e) { next(e); }
});
app.post("/api/wholesale-enquiries", enquiryLimiter, async (req, res, next) => {
  try {
    await connectDB(); const b = req.body || {}, name = clean(b.name, 120), email = clean(b.email, 254).toLowerCase(), phone = clean(b.phone, 30), message = clean(b.message, 3000);
    if (name.length < 2 || !validEmail(email) || phone.length < 7 || message.length < 10) return fail(res, 400, "Please complete the required fields.");
    const item = await Enquiry.create({ name, email, phone, message, enquiryType: "Wholesale partnership", businessName: clean(b.businessName, 200), businessType: clean(b.businessType, 100), quantity: clean(b.quantity, 100), location: clean(b.location, 200), packaging: clean(b.packaging, 200) });
    res.status(201).json({ ok: true, id: item._id, message: "Your wholesale enquiry has been received." });
  } catch (e) { next(e); }
});

/* Admin auth: configured hash only; no default admin is ever created. */
app.post("/api/admin/login", authLimiter, async (req, res, next) => {
  try {
    const email = clean(req.body.email, 254).toLowerCase(), password = String(req.body.password || "");
    if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD_HASH) return fail(res, 503, "Admin login is not configured.");
    const ok = email === process.env.ADMIN_EMAIL.toLowerCase() && await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH);
    if (!ok) return fail(res, 401, "Email or password is incorrect.");
    setCookie(res, sign({ sub: "admin", role: "admin" })); res.json({ ok: true });
  } catch (e) { next(e); }
});
app.post("/api/admin/logout", (req, res) => { res.clearCookie(COOKIE, { httpOnly: true, secure: isProd, sameSite: "lax", path: "/" }); res.json({ ok: true }); });
app.get("/api/admin/me", requireAdmin, (req, res) => res.json({ ok: true, email: process.env.ADMIN_EMAIL }));
app.get("/api/admin/dashboard", requireAdmin, async (req, res, next) => {
  try {
    await connectDB(); const since = req.query.from ? new Date(req.query.from) : new Date(Date.now() - 30 * 86400000), until = req.query.to ? new Date(req.query.to) : new Date();
    const [products, activeProducts, lowStock, outOfStock, orders, pendingOrders, customers, pendingEnquiries, revenueAgg, recentOrders, bestSellers] = await Promise.all([
      Product.countDocuments(), Product.countDocuments({ isActive: true }), Product.countDocuments({ isActive: true, inventory: { $gt: 0, $lte: 5 } }), Product.countDocuments({ isActive: true, inventory: 0 }),
      Order.countDocuments({ createdAt: { $gte: since, $lte: until } }), Order.countDocuments({ orderStatus: { $in: ["Pending Payment", "Confirmed", "Processing"] } }),
      User.countDocuments({ role: "customer" }), Enquiry.countDocuments({ status: "New" }),
      Order.aggregate([{ $match: { paymentStatus: "paid", createdAt: { $gte: since, $lte: until } } }, { $group: { _id: null, revenue: { $sum: "$total" } } }]),
      Order.find().sort({ createdAt: -1 }).limit(8).select("orderNumber customerDetails.name total paymentStatus orderStatus createdAt").lean(),
      Order.aggregate([{ $match: { paymentStatus: "paid" } }, { $unwind: "$items" }, { $group: { _id: "$items.name", quantity: { $sum: "$items.quantity" }, revenue: { $sum: "$items.lineTotal" } } }, { $sort: { quantity: -1 } }, { $limit: 5 }])
    ]);
    res.json({ ok: true, stats: { products, activeProducts, lowStock, outOfStock, orders, pendingOrders, customers, pendingEnquiries, revenue: revenueAgg[0]?.revenue || 0 }, recentOrders, bestSellers });
  } catch (e) { next(e); }
});
app.get("/api/admin/products", requireAdmin, async (req, res, next) => { try { await connectDB(); const page = Math.max(1, Number(req.query.page) || 1), limit = Math.min(100, Number(req.query.limit) || 30), q = clean(req.query.q, 100); const f = q ? { $or: [{ name: new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i") }, { sku: new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i") }] } : {}; const [items,total] = await Promise.all([Product.find(f).sort({ createdAt: -1 }).skip((page-1)*limit).limit(limit).lean(), Product.countDocuments(f)]); res.json({ ok: true, items, total, page }); } catch (e) { next(e); } });
function productInput(b, existing = {}) {
  const name = clean(b.name ?? existing.name, 120), category = clean(b.category ?? existing.category, 100), sku = clean(b.sku ?? existing.sku, 50).toUpperCase(), price = Number(b.price ?? existing.price), inventory = Number(b.inventory ?? existing.inventory ?? 0);
  if (name.length < 2 || !category || !/^[A-Z0-9_-]{2,50}$/.test(sku) || !Number.isFinite(price) || price < 0 || !Number.isInteger(inventory) || inventory < 0) throw Object.assign(new Error("Enter valid product name, category, SKU, price, and stock."), { status: 400 });
  const images = Array.isArray(b.images) ? b.images.slice(0, 6).map(x => clean(x, 1000)).filter(x => /^https:\/\/|^http:\/\//i.test(x)) : (existing.images || []);
  return { name, slug: slugify(b.slug || name), sku, category, price: rupees(price), inventory, unit: clean(b.unit ?? existing.unit ?? "1 kg", 50), description: clean(b.description ?? existing.description, 3000), images, isFeatured: Boolean(b.isFeatured ?? existing.isFeatured), isActive: b.isActive === undefined ? (existing.isActive ?? true) : Boolean(b.isActive), lowStockThreshold: Math.max(0, Number(b.lowStockThreshold ?? existing.lowStockThreshold ?? 5)), ingredients: clean(b.ingredients ?? existing.ingredients, 1000), storageInstructions: clean(b.storageInstructions ?? existing.storageInstructions, 1000), allergens: clean(b.allergens ?? existing.allergens, 500), weight: Math.max(0, Number(b.weight ?? existing.weight ?? 1)) };
}
app.post("/api/admin/products", requireAdmin, async (req, res, next) => { try { await connectDB(); const data = productInput(req.body); const item = await Product.create(data); res.status(201).json({ ok: true, item }); } catch (e) { if (e.code === 11000) return fail(res, 409, "Product SKU or slug already exists."); next(e); } });
app.patch("/api/admin/products/:id", requireAdmin, async (req, res, next) => { try { await connectDB(); if (!mongoose.isValidObjectId(req.params.id)) return fail(res, 400, "Invalid product ID."); const old = await Product.findById(req.params.id); if (!old) return fail(res, 404, "Product not found."); Object.assign(old, productInput(req.body, old.toObject())); await old.save(); res.json({ ok: true, item: old }); } catch (e) { if (e.code === 11000) return fail(res, 409, "Product SKU or slug already exists."); next(e); } });
app.delete("/api/admin/products/:id", requireAdmin, async (req, res, next) => { try { await connectDB(); const p = await Product.findByIdAndUpdate(req.params.id, { $set: { isActive: false } }, { new: true }); if (!p) return fail(res, 404, "Product not found."); res.json({ ok: true, message: "Product archived." }); } catch (e) { next(e); } });
app.get("/api/admin/categories", requireAdmin, async (req, res, next) => { try { await connectDB(); res.json({ ok: true, items: await Category.find().sort({ sortOrder: 1, name: 1 }).lean() }); } catch (e) { next(e); } });
app.post("/api/admin/categories", requireAdmin, async (req, res, next) => { try { await connectDB(); const name = clean(req.body.name, 100); if (name.length < 2) return fail(res, 400, "Category name is required."); const item = await Category.create({ name, slug: slugify(req.body.slug || name), description: clean(req.body.description, 1000), image: clean(req.body.image, 1000), sortOrder: Number(req.body.sortOrder) || 0 }); res.status(201).json({ ok: true, item }); } catch (e) { if (e.code === 11000) return fail(res, 409, "Category name or slug already exists."); next(e); } });
app.patch("/api/admin/categories/:id", requireAdmin, async (req, res, next) => { try { await connectDB(); const c = await Category.findById(req.params.id); if (!c) return fail(res, 404, "Category not found."); for (const k of ["name","description","image","isActive","sortOrder"]) if (req.body[k] !== undefined) c[k] = typeof c[k] === "number" ? Number(req.body[k]) : (typeof c[k] === "boolean" ? Boolean(req.body[k]) : clean(req.body[k], 1000)); if (req.body.slug) c.slug = slugify(req.body.slug); await c.save(); res.json({ ok: true, item: c }); } catch (e) { next(e); } });
app.delete("/api/admin/categories/:id", requireAdmin, async (req, res, next) => { try { await connectDB(); const c = await Category.findByIdAndUpdate(req.params.id, { isActive: false }, { new: true }); if (!c) return fail(res, 404, "Category not found."); res.json({ ok: true }); } catch (e) { next(e); } });
app.get("/api/admin/orders", requireAdmin, async (req, res, next) => { try { await connectDB(); const page = Math.max(1, Number(req.query.page) || 1), limit = Math.min(100, Number(req.query.limit) || 30), f = {}; if (req.query.status) f.orderStatus = clean(req.query.status, 60); if (req.query.paymentStatus) f.paymentStatus = clean(req.query.paymentStatus, 30); const [items,total] = await Promise.all([Order.find(f).sort({ createdAt: -1 }).skip((page-1)*limit).limit(limit).lean(), Order.countDocuments(f)]); res.json({ ok: true, items, total, page }); } catch (e) { next(e); } });
app.get("/api/admin/orders/:id", requireAdmin, async (req, res, next) => { try { await connectDB(); const o = await Order.findById(req.params.id).lean(); if (!o) return fail(res, 404, "Order not found."); res.json({ ok: true, item: o }); } catch (e) { next(e); } });
const allowedTransitions = { "Confirmed": ["Processing","Cancelled"], "Processing": ["Packed","Cancelled"], "Packed": ["Shipped"], "Shipped": ["Out for Delivery"], "Out for Delivery": ["Delivered"], "Pending Payment": ["Cancelled"], "Refund Pending": ["Refunded"] };
app.patch("/api/admin/orders/:id", requireAdmin, async (req, res, next) => {
  try {
    await connectDB(); const o = await Order.findById(req.params.id); if (!o) return fail(res, 404, "Order not found.");
    if (req.body.orderStatus) {
      const nextStatus = clean(req.body.orderStatus, 50);
      if (nextStatus !== o.orderStatus && !(allowedTransitions[o.orderStatus] || []).includes(nextStatus)) return fail(res, 400, `Invalid order status transition from ${o.orderStatus}.`);
      if (nextStatus === "Cancelled" && o.paymentStatus === "paid") return fail(res, 409, "Paid orders require a refund workflow before cancellation.");
      o.orderStatus = nextStatus; o.statusHistory.push({ status: nextStatus, note: "Updated by administrator" });
      if (nextStatus === "Cancelled" && o.inventoryCommitted) { for (const i of o.items) await Product.updateOne({ _id: i.productId }, { $inc: { inventory: i.quantity } }); o.inventoryCommitted = false; }
    }
    if (req.body.trackingNumber !== undefined) o.trackingNumber = clean(req.body.trackingNumber, 100);
    if (req.body.trackingUrl !== undefined) { const u = clean(req.body.trackingUrl, 1000); if (u && !/^https:\/\//i.test(u)) return fail(res, 400, "Tracking URL must use HTTPS."); o.trackingUrl = u; }
    if (req.body.adminNotes !== undefined) o.adminNotes = clean(req.body.adminNotes, 2000);
    await o.save(); res.json({ ok: true, item: o });
  } catch (e) { next(e); }
});
app.get("/api/admin/customers", requireAdmin, async (req, res, next) => { try { await connectDB(); const page = Math.max(1, Number(req.query.page) || 1), items = await User.find({ role: "customer" }).select("name email phone isActive createdAt").sort({ createdAt: -1 }).skip((page-1)*50).limit(50).lean(); res.json({ ok: true, items }); } catch (e) { next(e); } });
app.get("/api/admin/enquiries", requireAdmin, async (req, res, next) => { try { await connectDB(); const f = {}; if (req.query.status) f.status = clean(req.query.status, 30); const items = await Enquiry.find(f).sort({ createdAt: -1 }).limit(200).lean(); res.json({ ok: true, items }); } catch (e) { next(e); } });
app.patch("/api/admin/enquiries/:id", requireAdmin, async (req, res, next) => { try { await connectDB(); const status = clean(req.body.status, 30); if (!["New","In Progress","Responded","Closed"].includes(status)) return fail(res, 400, "Invalid enquiry status."); const item = await Enquiry.findByIdAndUpdate(req.params.id, { $set: { status, ...(req.body.internalNotes !== undefined ? { internalNotes: clean(req.body.internalNotes, 2000) } : {}) } }, { new: true, runValidators: true }); if (!item) return fail(res, 404, "Enquiry not found."); res.json({ ok: true, item }); } catch (e) { next(e); } });
app.get("/api/admin/coupons", requireAdmin, async (req, res, next) => { try { await connectDB(); res.json({ ok: true, items: await Coupon.find().sort({ createdAt: -1 }).limit(200).lean() }); } catch (e) { next(e); } });
app.post("/api/admin/coupons", requireAdmin, async (req, res, next) => { try { await connectDB(); const code = clean(req.body.code, 40).toUpperCase(), discountType = req.body.discountType; const discountValue = Number(req.body.discountValue); if (!/^[A-Z0-9_-]{3,40}$/.test(code) || !["percentage","fixed"].includes(discountType) || !Number.isFinite(discountValue) || discountValue <= 0 || (discountType === "percentage" && discountValue > 100)) return fail(res, 400, "Coupon details are invalid."); const item = await Coupon.create({ code, discountType, discountValue, minimumOrderValue: Math.max(0, Number(req.body.minimumOrderValue) || 0), maximumDiscount: req.body.maximumDiscount ? Number(req.body.maximumDiscount) : undefined, usageLimit: req.body.usageLimit ? Number(req.body.usageLimit) : undefined, perCustomerLimit: Math.max(1, Number(req.body.perCustomerLimit) || 1), startDate: req.body.startDate ? new Date(req.body.startDate) : undefined, expiryDate: req.body.expiryDate ? new Date(req.body.expiryDate) : undefined, isActive: req.body.isActive !== false }); res.status(201).json({ ok: true, item }); } catch (e) { if (e.code === 11000) return fail(res, 409, "Coupon code already exists."); next(e); } });
app.patch("/api/admin/coupons/:id", requireAdmin, async (req, res, next) => { try { await connectDB(); const c = await Coupon.findById(req.params.id); if (!c) return fail(res, 404, "Coupon not found."); if (req.body.isActive !== undefined) c.isActive = Boolean(req.body.isActive); if (req.body.expiryDate !== undefined) c.expiryDate = req.body.expiryDate ? new Date(req.body.expiryDate) : null; await c.save(); res.json({ ok: true, item: c }); } catch (e) { next(e); } });
app.get("/api/admin/inventory", requireAdmin, async (req, res, next) => { try { await connectDB(); const items = await Product.find().select("name sku inventory lowStockThreshold isActive").sort({ inventory: 1 }).limit(300).lean(); res.json({ ok: true, items }); } catch (e) { next(e); } });
app.post("/api/admin/inventory/adjust", requireAdmin, async (req, res, next) => { try { await connectDB(); const { productId } = req.body, delta = Number(req.body.quantityChange), reason = clean(req.body.reason, 250); if (!mongoose.isValidObjectId(productId) || !Number.isInteger(delta) || delta === 0 || Math.abs(delta) > 100000 || reason.length < 3) return fail(res, 400, "Valid product, non-zero integer adjustment, and reason are required."); const filter = { _id: productId, ...(delta < 0 ? { inventory: { $gte: -delta } } : {}) }; const p = await Product.findOneAndUpdate(filter, { $inc: { inventory: delta } }, { new: true }); if (!p) return fail(res, 409, "Product not found or stock cannot go below zero."); await InventoryMovement.create({ productId, quantityChange: delta, reason, adminId: null }); res.json({ ok: true, item: p }); } catch (e) { next(e); } });
app.get("/api/admin/reports/sales", requireAdmin, async (req, res, next) => { try { await connectDB(); const since = req.query.from ? new Date(req.query.from) : new Date(Date.now()-30*86400000), until = req.query.to ? new Date(req.query.to) : new Date(); const data = await Order.aggregate([{ $match: { createdAt: { $gte: since, $lte: until }, paymentStatus: "paid" } }, { $group: { _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } }, revenue: { $sum: "$total" }, orders: { $sum: 1 } } }, { $sort: { _id: 1 } }]); res.json({ ok: true, items: data }); } catch (e) { next(e); } });
app.get("/api/admin/reports/inventory", requireAdmin, async (req, res, next) => { try { await connectDB(); const items = await Product.find({ $or: [{ inventory: 0 }, { $expr: { $lte: ["$inventory", "$lowStockThreshold"] } }] }).select("name sku inventory lowStockThreshold").sort({ inventory: 1 }).lean(); res.json({ ok: true, items }); } catch (e) { next(e); } });
app.get("/api/admin/reports/export.csv", requireAdmin, async (req, res, next) => { try { await connectDB(); const items = await Order.find().sort({ createdAt: -1 }).limit(5000).lean(); const esc = v => '"' + String(v ?? "").replace(/"/g, '""').replace(/[\r\n]+/g, " ") + '"'; const rows = [["Order","Created","Customer","Email","Total INR","Payment","Status"], ...items.map(o => [o.orderNumber,o.createdAt?.toISOString(),o.customerDetails?.name,o.customerDetails?.email,o.total,o.paymentStatus,o.orderStatus])]; res.setHeader("Content-Type","text/csv; charset=utf-8"); res.setHeader("Content-Disposition",'attachment; filename="rp-agro-orders.csv"'); res.send(rows.map(r => r.map(esc).join(",")).join("\r\n")); } catch (e) { next(e); } });

/* Authorized one-time seed: POST /api/admin/seed with { "confirm": "SEED_DEMO_DATA" } */
app.post("/api/admin/seed", requireAdmin, async (req, res, next) => {
  try {
    await connectDB(); if (req.body.confirm !== "SEED_DEMO_DATA") return fail(res, 400, "Explicit seed confirmation required.");
    if (await Product.countDocuments() || await Category.countDocuments()) return fail(res, 409, "Seed only works on an empty catalogue.");
    const cats = [
      ["Rice and Grains","Everyday grains for your kitchen","https://images.unsplash.com/photo-1586201375761-83865001e31c?w=700"],
      ["Pulses and Lentils","Kitchen staples for daily meals","https://images.unsplash.com/photo-1515543904379-3d757ceed4c2?w=700"],
      ["Wheat and Flour","Flours and traditional staples","https://images.unsplash.com/photo-1574323347407-f5e1ad6d020b?w=700"],
      ["Spices and Masalas","Aromatic essentials for cooking","https://images.unsplash.com/photo-1596040033229-a9821ebd058d?w=700"],
      ["Cooking Essentials","Useful pantry ingredients","https://images.unsplash.com/photo-1474979266404-7eaacbcd87c5?w=700"],
      ["Jaggery and Natural Sweeteners","Traditional sweetening essentials","https://images.unsplash.com/photo-1587049352851-8d4e89133924?w=700"],
      ["Dry Fruits and Seeds","Versatile seeds and dry pantry goods","https://images.unsplash.com/photo-1505576399274-565b52d4ac71?w=700"],
      ["Special Agro Products","More pantry favourites","https://images.unsplash.com/photo-1547592180-85f173990554?w=700"]
    ];
    await Category.insertMany(cats.map((c,i)=>({ name:c[0],slug:slugify(c[0]),description:c[1],image:c[2],sortOrder:i })));
    const samples = [
      ["Premium Basmati Rice","Rice and Grains",180,"1 kg","photo-1586201375761-83865001e31c"],
      ["Toor Dal","Pulses and Lentils",145,"1 kg","photo-1515543904379-3d757ceed4c2"],
      ["Whole Wheat Flour","Wheat and Flour",65,"1 kg","photo-1574323347407-f5e1ad6d020b"],
      ["Turmeric Powder","Spices and Masalas",90,"200 g","photo-1615485500704-8e990f9900f5"],
      ["Red Chilli Powder","Spices and Masalas",110,"200 g","photo-辣"],
      ["Jaggery Powder","Jaggery and Natural Sweeteners",80,"500 g","photo-1587049352851-8d4e89133924"],
      ["Moong Dal","Pulses and Lentils",130,"1 kg","photo-1515543904379-3d757ceed4c2"],
      ["Chana Dal","Pulses and Lentils",95,"1 kg","photo-1515543904379-3d757ceed4c2"],
      ["Groundnut Seeds","Dry Fruits and Seeds",120,"1 kg","photo-1505576399274-565b52d4ac71"],
      ["Coriander Powder","Spices and Masalas",75,"200 g","photo-1596040033229-a9821ebd058d"],
      ["Premium Poha","Rice and Grains",60,"1 kg","photo-1547592180-85f173990554"],
      ["Roasted Chana","Pulses and Lentils",90,"500 g","photo-1515543904379-3d757ceed4c2"]
    ];
    const products = samples.map((p,i)=>({ name:p[0],slug:slugify(p[0]),sku:"RPA"+String(i+1).padStart(4,"0"),category:p[1],price:p[2],unit:p[3],inventory:30,lowStockThreshold:5,description:"Demonstration catalogue item. Confirm product specifications and supplier details before selling.",images:[p[4]==="photo-辣"?"https://images.unsplash.com/photo-1596040033229-a9821ebd058d?w=900":`https://images.unsplash.com/${p[4]}?auto=format&fit=crop&w=900&q=80`],isFeatured:i<8,isActive:true }));
    await Product.insertMany(products); res.json({ ok: true, message: "Demo categories and products created.", productCount: products.length, categoryCount: cats.length });
  } catch (e) { next(e); }
});

const homeHtml = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#245c3a"><meta name="description" content="RP Agro Food — grains, pulses, spices and pantry essentials."><title>RP Agro Food — From Our Farms to Your Family</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&family=Poppins:wght@500;600;700;800&display=swap" rel="stylesheet"><script src="https://checkout.razorpay.com/v1/checkout.js" defer></script>
<style>
:root{--forest:#245c3a;--leaf:#68b984;--cream:#fff8e8;--yellow:#f4c95d;--terra:#d9825b;--sage:#ddeddd;--ink:#24332a;--muted:#65766a;--white:#fff;--shadow:12px 12px 28px #c8d7c7,-10px -10px 26px #fff;--soft:7px 7px 18px #d2dfd0,-7px -7px 18px #fff}*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--cream);color:var(--ink);font-family:Manrope,system-ui,sans-serif}button,input,select,textarea{font:inherit}button,a{cursor:pointer}a{color:inherit;text-decoration:none}.announcement{background:var(--forest);color:#fff;padding:9px 16px;text-align:center;font-size:12px;letter-spacing:.3px}.nav{position:sticky;top:0;z-index:10;background:#fff8e8ed;backdrop-filter:blur(15px);border-bottom:1px solid #e4eadf}.navin{max-width:1180px;margin:auto;padding:14px 22px;display:flex;align-items:center;gap:22px}.brand{display:flex;align-items:center;gap:10px;font-family:Poppins,sans-serif;font-weight:800;color:var(--forest);font-size:20px;white-space:nowrap}.leaflogo{width:42px;height:42px;display:grid;place-items:center;background:var(--sage);border-radius:15px;box-shadow:var(--soft);font-size:24px}.links{display:flex;gap:19px;margin-left:auto;font-size:13px;font-weight:700}.links a:hover{color:var(--terra)}.navactions{display:flex;gap:8px}.pill,.btn{border:0;border-radius:16px;padding:12px 17px;font-weight:800;box-shadow:var(--soft);background:#fff;color:var(--forest);transition:transform .2s,box-shadow .2s}.pill:hover,.btn:hover{transform:translateY(-2px)}.btn.primary{background:var(--forest);color:white}.btn.sun{background:var(--yellow);color:#3d3418}.cartcount{background:var(--terra);color:white;border-radius:99px;padding:2px 7px;font-size:11px}.menu{display:none}.hero{max-width:1180px;margin:32px auto 55px;padding:35px 22px;display:grid;grid-template-columns:1fr 1fr;gap:40px;align-items:center}.eyebrow{display:inline-flex;background:#e5f1df;color:var(--forest);border-radius:99px;padding:9px 14px;font-weight:800;font-size:12px;box-shadow:var(--soft)}h1,h2,h3{font-family:Poppins,Manrope,sans-serif;line-height:1.13}h1{font-size:clamp(38px,5vw,66px);letter-spacing:-2.2px;margin:22px 0}h1 span{color:var(--forest)}.hero p{font-size:17px;line-height:1.8;color:var(--muted);max-width:520px}.herobtns{display:flex;gap:12px;flex-wrap:wrap;margin-top:26px}.heroimg{position:relative;min-height:420px;border-radius:42px;background:var(--sage);padding:18px;box-shadow:var(--shadow);transform:rotate(1deg)}.heroimg img{width:100%;height:390px;object-fit:cover;border-radius:30px}.floatcard{position:absolute;left:-18px;bottom:28px;background:#fff;border-radius:20px;padding:15px 18px;box-shadow:var(--shadow);font-weight:800}.floatbadge{position:absolute;right:-15px;top:25px;border-radius:50%;width:94px;height:94px;background:var(--yellow);display:grid;place-items:center;text-align:center;font-weight:900;transform:rotate(9deg);box-shadow:var(--shadow)}.truststrip{max-width:1120px;margin:0 auto 65px;display:grid;grid-template-columns:repeat(4,1fr);gap:15px;padding:0 22px}.trust{padding:19px;border-radius:20px;background:#fff;box-shadow:var(--soft);display:flex;gap:12px;align-items:center;font-size:13px;font-weight:800}.trust b{font-size:23px}.section{max-width:1180px;margin:0 auto;padding:30px 22px 65px}.sectionhead{display:flex;align-items:end;justify-content:space-between;gap:20px;margin-bottom:25px}.sectionhead h2{font-size:clamp(28px,3vw,40px);margin:8px 0}.muted{color:var(--muted);line-height:1.7}.categories{display:grid;grid-template-columns:repeat(4,1fr);gap:18px}.cat{border-radius:26px;padding:14px;background:#fff;box-shadow:var(--soft);transition:.25s;cursor:pointer}.cat:hover,.product:hover{transform:translateY(-5px);box-shadow:var(--shadow)}.cat img{width:100%;height:140px;object-fit:cover;border-radius:18px}.cat h3{font-size:17px;margin:13px 3px 6px}.cat p{font-size:12px;color:var(--muted);margin:0 3px 10px;line-height:1.6}.products{display:grid;grid-template-columns:repeat(4,1fr);gap:18px}.toolbar{display:flex;gap:10px;flex-wrap:wrap;margin:18px 0 24px}.field{background:#fff;border:1px solid #e4eadd;border-radius:14px;padding:12px 14px;box-shadow:inset 3px 3px 8px #e5eadd,inset -3px -3px 8px #fff;min-width:140px}.field.search{flex:1;min-width:220px}.product{background:#fff;border-radius:25px;padding:13px;box-shadow:var(--soft);transition:.25s;position:relative;overflow:hidden}.product img{width:100%;height:190px;object-fit:cover;border-radius:18px;background:var(--sage)}.product .tag{position:absolute;top:22px;left:22px;background:var(--yellow);padding:6px 9px;border-radius:99px;font-size:10px;font-weight:900}.product h3{font-size:16px;margin:14px 2px 4px}.product .meta{font-size:11px;color:var(--muted)}.price{font-size:19px;font-weight:900;color:var(--forest);margin:12px 2px}.price small{font-size:11px;font-weight:600;color:var(--muted)}.prodactions{display:flex;gap:8px}.prodactions button{flex:1;padding:10px 8px;font-size:12px}.widebanner{max-width:1136px;margin:0 auto 65px;border-radius:35px;padding:45px;background:linear-gradient(125deg,#245c3a,#4f9561);color:white;box-shadow:var(--shadow);display:flex;justify-content:space-between;align-items:center;gap:25px}.widebanner h2{font-size:35px;margin:0 0 10px}.widebanner p{line-height:1.7;color:#e6f2e6}.aboutgrid{display:grid;grid-template-columns:1fr 1fr;gap:35px;align-items:center}.aboutgrid img{width:100%;height:330px;object-fit:cover;border-radius:32px;box-shadow:var(--shadow)}.qualitygrid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px}.quality{background:#fff;border-radius:24px;padding:25px;box-shadow:var(--soft)}.quality .ico{font-size:30px}.quality h3{font-size:17px}.quality p{font-size:13px;color:var(--muted);line-height:1.7}.contactgrid{display:grid;grid-template-columns:.8fr 1.2fr;gap:24px}.contactinfo,.formbox{background:#fff;border-radius:28px;padding:28px;box-shadow:var(--soft)}.formgrid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.formbox input,.formbox textarea,.formbox select{width:100%;border:1px solid #e2e9de;background:#fcfdf9;border-radius:13px;padding:13px;margin-bottom:12px}.formbox textarea{min-height:115px;resize:vertical}.formbox label{font-size:12px;font-weight:800}.footer{background:#1d4b30;color:white;padding:45px 22px 22px}.footerin{max-width:1136px;margin:auto;display:grid;grid-template-columns:2fr 1fr 1fr;gap:30px}.footer p,.footer a{font-size:13px;line-height:1.9;color:#d9e8db}.copyright{border-top:1px solid #ffffff2e;margin-top:25px;padding-top:18px;text-align:center;font-size:12px;color:#c8ddcc}.modal{position:fixed;inset:0;z-index:30;background:#18281dcc;display:none;align-items:center;justify-content:center;padding:18px}.modal.open{display:flex}.modalbox{background:var(--cream);max-width:700px;width:100%;max-height:90vh;overflow:auto;border-radius:28px;padding:25px;box-shadow:var(--shadow);animation:pop .25s ease}.modalhead{display:flex;justify-content:space-between;align-items:center}.close{border:0;background:var(--sage);border-radius:50%;width:38px;height:38px;font-size:20px}.toast{position:fixed;bottom:22px;right:22px;z-index:50;background:var(--forest);color:white;padding:14px 18px;border-radius:15px;box-shadow:var(--shadow);opacity:0;transform:translateY(12px);transition:.25s;pointer-events:none}.toast.show{opacity:1;transform:translateY(0)}.empty{grid-column:1/-1;padding:40px;text-align:center;background:#fff;border-radius:22px;color:var(--muted)}.reveal{animation:rise .6s both}@keyframes rise{from{opacity:0;transform:translateY(18px)}to{opacity:1;transform:translateY(0)}}@keyframes pop{from{opacity:0;transform:scale(.96)}to{opacity:1;transform:scale(1)}}@media(prefers-reduced-motion:reduce){*,*:before,*:after{scroll-behavior:auto!important;animation:none!important;transition:none!important}}@media(max-width:900px){.links{display:none}.menu{display:block}.hero{grid-template-columns:1fr;gap:25px}.heroimg{min-height:300px}.heroimg img{height:310px}.categories,.products{grid-template-columns:repeat(2,1fr)}.truststrip{grid-template-columns:repeat(2,1fr)}.contactgrid,.aboutgrid{grid-template-columns:1fr}.footerin{grid-template-columns:1fr 1fr}}@media(max-width:560px){.navin{padding:12px}.brand{font-size:16px}.navactions .pill{padding:10px}.hero{padding:22px 17px;margin-top:10px}.heroimg{padding:10px;border-radius:28px}.heroimg img{height:260px}.floatbadge{width:75px;height:75px;right:-4px}.floatcard{left:0;bottom:12px}.section{padding:25px 16px 45px}.categories,.products{gap:11px}.cat{padding:9px;border-radius:19px}.cat img{height:100px}.cat h3{font-size:13px}.product{padding:9px;border-radius:19px}.product img{height:135px}.product h3{font-size:13px}.prodactions{flex-direction:column}.truststrip{padding:0 16px;gap:10px}.trust{padding:12px;font-size:11px}.widebanner{margin:0 14px 40px;padding:25px;display:block}.widebanner h2{font-size:27px}.formgrid{grid-template-columns:1fr}.footerin{grid-template-columns:1fr}.sectionhead{align-items:start;flex-direction:column}}
</style></head><body>
<div class="announcement">🌾 Welcome to RP Agro Food — Goodness in Every Grain! &nbsp; • &nbsp; Secure online checkout when configured</div>
<header class="nav"><div class="navin"><a class="brand" href="#"><span class="leaflogo">🌿</span><span>RP Agro Food<small style="display:block;font:600 9px Manrope;color:#748575;letter-spacing:1px">PURE GOODNESS · NATURAL HARVEST</small></span></a><nav class="links"><a href="#home">Home</a><a href="#shop">Shop</a><a href="#categories">Categories</a><a href="#about">Our Story</a><a href="#quality">Our Quality</a><a href="#contact">Contact</a></nav><div class="navactions"><button class="pill" onclick="account()">♙</button><button class="pill" onclick="openCart()">🛒 <span class="cartcount" id="cartCount">0</span></button><button class="pill menu" onclick="document.getElementById('categories').scrollIntoView()">☰</button></div></div></header>
<main id="home"><section class="hero"><div class="reveal"><span class="eyebrow">🌱 EVERYDAY PANTRY, MADE LOVELY</span><h1>Nature’s Best,<br><span>Delivered to</span><br>Your Doorstep.</h1><p>Discover quality grains, pulses, spices, and everyday food essentials, carefully selected for your kitchen.</p><div class="herobtns"><a class="btn primary" href="#shop">Shop Our Products →</a><a class="btn" href="#categories">Explore Categories</a></div><p style="font-size:12px;margin-top:22px">🌾 Thoughtful staples · Simple shopping · Friendly support</p></div><div class="heroimg reveal"><img src="https://images.unsplash.com/photo-1500382017468-9049fed747ef?auto=format&fit=crop&w=1100&q=85" alt="Golden agricultural fields under a bright sky" onerror="this.src='https://images.unsplash.com/photo-1472396961693-142e6e269027?w=1000'"><div class="floatcard">🌿 Goodness for every day<br><small style="color:#748575">Your kitchen, your essentials</small></div><div class="floatbadge">FRESH<br>FINDS ✨</div></div></section>
<div class="truststrip"><div class="trust"><b>🌾</b><span>Everyday pantry<br>essentials</span></div><div class="trust"><b>📦</b><span>Careful order<br>handling</span></div><div class="trust"><b>🔒</b><span>Secure checkout<br>when enabled</span></div><div class="trust"><b>💚</b><span>Customer-first<br>support</span></div></div>
<section class="section" id="categories"><div class="sectionhead"><div><span class="eyebrow">EXPLORE THE PANTRY</span><h2>Shop by category</h2><p class="muted">A little something for every kitchen shelf.</p></div></div><div class="categories" id="categoryGrid"><div class="empty">Loading categories…</div></div></section>
<section class="section" id="shop" style="background:#eaf2e5;border-radius:36px;margin-bottom:50px"><div class="sectionhead"><div><span class="eyebrow">PICKED FOR YOUR PANTRY</span><h2>Everyday favourites</h2><p class="muted">Browse our catalogue and find your kitchen essentials.</p></div><button class="btn" onclick="clearFilters()">Clear filters ↺</button></div><div class="toolbar"><input id="search" class="field search" placeholder="Search products or SKU…" oninput="debouncedLoad()"><select id="categoryFilter" class="field" onchange="loadProducts()"><option value="">All categories</option></select><select id="sort" class="field" onchange="loadProducts()"><option value="newest">Newest</option><option value="price-asc">Price: low to high</option><option value="price-desc">Price: high to low</option><option value="name">Name A–Z</option></select><select id="availability" class="field" onchange="loadProducts()"><option value="">All availability</option><option value="true">In stock</option></select></div><div class="products" id="productGrid"><div class="empty">Loading products…</div></div><div style="text-align:center;margin-top:24px"><button class="btn" id="moreBtn" style="display:none" onclick="loadProducts(true)">Load more products ↓</button></div></section>
<section class="widebanner"><div><span class="eyebrow" style="background:#ffffff22;color:white">BULK & WHOLESALE</span><h2>Buying for a business?</h2><p>Tell us what you need, your approximate quantity, and preferred packaging.<br>Our team can review your enquiry and discuss availability.</p></div><button class="btn sun" onclick="document.getElementById('wholesale').scrollIntoView({behavior:'smooth'})">Talk to our team →</button></section>
<section class="section" id="about"><div class="aboutgrid"><div><span class="eyebrow">A LITTLE ABOUT US</span><h2 style="font-size:38px">Good food starts with thoughtful choices.</h2><p class="muted">RP Agro Food brings a curated range of grains, pulses, spices, and pantry staples together in one convenient place. We believe shopping for everyday essentials should feel clear, friendly, and dependable.</p><p class="muted">Product details and sourcing information are shared where supplied and verified. We keep our catalogue practical, our ordering experience simple, and our customer support approachable.</p><a class="btn primary" href="#shop">Explore the collection</a></div><img src="https://images.unsplash.com/photo-1499529112087-3cb3b73_ce4d?auto=format&fit=crop&w=1000&q=80" alt="Fresh produce and agricultural harvest" onerror="this.style.display='none'"></div></section>
<section class="section" id="quality"><div class="sectionhead"><div><span class="eyebrow">WHAT MATTERS TO US</span><h2>Simple, thoughtful service</h2><p class="muted">Clear product information and a smooth experience, from browsing to delivery.</p></div></div><div class="qualitygrid"><article class="quality"><div class="ico">🔎</div><h3>Clear product details</h3><p>Review package sizes, prices, availability, and any supplied storage or ingredient information before ordering.</p></article><article class="quality"><div class="ico">📦</div><h3>Careful order handling</h3><p>Orders and inventory are recorded in the system so the team can manage fulfilment and stock.</p></article><article class="quality"><div class="ico">🤝</div><h3>Customer-first support</h3><p>Use the enquiry form for product questions, bulk requirements, and general assistance.</p></article></div></section>
<section class="section" id="wholesale"><div class="contactgrid"><div class="contactinfo"><span class="eyebrow">WHOLESALE & BULK</span><h2>Let’s talk quantities.</h2><p class="muted">For retailers, restaurants, distributors, and business buyers. Wholesale pricing is subject to review and approval.</p><p>📍 Shop No. 12, Green Market Complex, Pune, Maharashtra, India</p><p>🕘 Monday–Saturday, 9:00 AM–7:00 PM</p><p>✉️ hello@rpagrofood.example</p><p style="font-size:11px;color:#7c897e">Demonstration contact details — replace before launch.</p></div><form class="formbox" id="wholesaleForm"><h3>Wholesale enquiry</h3><div class="formgrid"><div><label>Business name</label><input name="businessName" required maxlength="200"></div><div><label>Contact person</label><input name="name" required maxlength="120"></div><div><label>Email</label><input name="email" type="email" required></div><div><label>Phone</label><input name="phone" required></div><div><label>Business type</label><select name="businessType"><option>Retailer</option><option>Restaurant</option><option>Wholesaler</option><option>Distributor</option><option>Other</option></select></div><div><label>Approximate quantity</label><input name="quantity" placeholder="e.g. 100 kg"></div></div><label>Delivery location</label><input name="location"><label>Product and packaging requirements</label><textarea name="message" required minlength="10" placeholder="Tell us about the products and quantities you need…"></textarea><input name="packaging" placeholder="Preferred packaging (optional)"><button class="btn primary" type="submit">Send wholesale enquiry →</button></form></div></section>
<section class="section" id="contact"><div class="contactgrid"><div><span class="eyebrow">WE’RE HERE TO HELP</span><h2 style="font-size:35px">Have a question?</h2><p class="muted">Ask about products, availability, or your shopping experience. Our sample contact information must be replaced with verified business details before launch.</p><p>✉️ hello@rpagrofood.example</p><p>☎️ +91 90000 12345</p></div><form class="formbox" id="enquiryForm"><h3>Send an enquiry</h3><div class="formgrid"><input name="name" placeholder="Full name" required maxlength="120"><input name="email" type="email" placeholder="Email address" required><input name="phone" placeholder="Mobile number" required><select name="enquiryType"><option>General enquiry</option><option>Product enquiry</option><option>Bulk order</option><option>Wholesale partnership</option><option>Retail partnership</option><option>Distribution enquiry</option><option>Custom packaging</option></select></div><input name="productInterest" placeholder="Product of interest (optional)"><input name="quantity" placeholder="Quantity required (optional)"><textarea name="message" placeholder="How can we help?" minlength="10" required></textarea><div style="position:absolute;left:-10000px" aria-hidden="true"><input name="website" tabindex="-1" autocomplete="off"></div><button class="btn primary" type="submit">Send message →</button></form></div></section></main>
<footer class="footer"><div class="footerin"><div><div class="brand" style="color:white"><span class="leaflogo">🌿</span>RP Agro Food</div><p>From Our Farms to Your Family.<br>Everyday pantry essentials, thoughtfully presented.</p><p>Shop No. 12, Green Market Complex, Pune, Maharashtra, India</p></div><div><h3>Explore</h3><p><a href="#shop">Shop products</a><br><a href="#categories">Categories</a><br><a href="#about">About us</a><br><a href="#quality">Our quality</a></p></div><div><h3>Customer care</h3><p><a href="#contact">Contact & enquiries</a><br><a href="#wholesale">Bulk orders</a><br><a href="#" onclick="policy('Shipping policy','Delivery charges and estimates are shown at checkout where configured. Please contact support for current delivery coverage.')">Shipping policy</a><br><a href="#" onclick="policy('Returns & refunds','Return and refund terms should be confirmed by the business before launch. Contact support for assistance.')">Returns & refunds</a><br><a href="#" onclick="policy('Privacy policy','This demonstration site stores order and enquiry data in its configured database. Publish a reviewed privacy policy before launch.')">Privacy policy</a><br><a href="#" onclick="policy('Terms & conditions','Replace this demonstration text with reviewed terms before accepting real orders.')">Terms & conditions</a></p></div></div><div class="copyright">© <span id="year"></span> RP Agro Food. Demonstration storefront — replace dummy business details before launch.</div></footer>
<div class="modal" id="modal" role="dialog" aria-modal="true" aria-label="Store dialog"><div class="modalbox"><div class="modalhead"><h2 id="modalTitle">Your cart</h2><button class="close" onclick="closeModal()" aria-label="Close dialog">×</button></div><div id="modalBody"></div></div></div><div class="toast" id="toast" role="status"></div>
<script>
const $=s=>document.querySelector(s);let products=[],categories=[],page=1,pages=1,cart=JSON.parse(localStorage.getItem('rpaf_cart')||'[]'),wishlist=JSON.parse(localStorage.getItem('rpaf_wish')||'[]'),searchTimer;
function esc(s=''){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function money(n){return '₹'+Number(n||0).toLocaleString('en-IN',{maximumFractionDigits:2})}
function toast(t){$('#toast').textContent=t;$('#toast').classList.add('show');setTimeout(()=>$('#toast').classList.remove('show'),2600)}
async function api(url,opts={}){const r=await fetch(url,{credentials:'same-origin',headers:{'Content-Type':'application/json',...(opts.headers||{})},...opts});let d={};try{d=await r.json()}catch{}if(!r.ok)throw new Error(d.error||'Something went wrong. Please try again.');return d}
function imgSrc(p){return p.images&&p.images[0]||'https://images.unsplash.com/photo-1547592180-85f173990554?w=800'}
async function loadCategories(){try{const d=await api('/api/categories');categories=d.items;$('#categoryGrid').innerHTML=categories.length?categories.map(c=>\`<article class="cat" onclick="chooseCategory('\${esc(c.name)}')"><img loading="lazy" src="\${esc(c.image||'https://images.unsplash.com/photo-1547592180-85f173990554?w=700')}" alt="\${esc(c.name)}" onerror="this.src='https://images.unsplash.com/photo-1547592180-85f173990554?w=700'"><h3>\${esc(c.name)}</h3><p>\${esc(c.description||'Everyday pantry essentials')} · \${c.productCount||0} products</p></article>\`).join(''):'<div class="empty">No categories yet. Please check back soon.</div>';$('#categoryFilter').innerHTML='<option value="">All categories</option>'+categories.map(c=>\`<option>\${esc(c.name)}</option>\`).join('')}catch(e){$('#categoryGrid').innerHTML='<div class="empty">Categories are temporarily unavailable.</div>'}}
async function loadProducts(append=false){if(!append)page=1;const params=new URLSearchParams({page,limit:12,sort:$('#sort').value});if($('#search').value.trim())params.set('q',$('#search').value.trim());if($('#categoryFilter').value)params.set('category',$('#categoryFilter').value);if($('#availability').value)params.set('available',$('#availability').value);try{const d=await api('/api/products?'+params);products=append?products.concat(d.items):d.items;pages=d.pages;renderProducts(append);$('#moreBtn').style.display=page<pages?'inline-block':'none'}catch(e){$('#productGrid').innerHTML=\`<div class="empty">\${esc(e.message)}</div>\`}}
function renderProducts(append=false){const html=products.map(p=>\`<article class="product"><span class="tag">\${p.inventory>0?'IN STOCK':'SOLD OUT'}</span><img loading="lazy" src="\${esc(imgSrc(p))}" alt="\${esc(p.name)}" onerror="this.src='https://images.unsplash.com/photo-1547592180-85f173990554?w=800'"><div class="meta">\${esc(p.category)} · \${esc(p.sku)}</div><h3>\${esc(p.name)}</h3><div class="meta">\${esc(p.unit||'')}</div><div class="price">\${money(p.price)} <small>/ \${esc(p.unit||'unit')}</small></div><div class="prodactions"><button class="btn primary" \${p.inventory<1?'disabled':''} onclick="addCart('\${p._id}')">Add to cart</button><button class="btn" onclick="details('\${p.slug}')">Details</button><button class="btn" aria-label="Wishlist" onclick="wish('\${p._id}')">\${wishlist.includes(p._id)?'♥':'♡'}</button></div></article>\`).join('');$('#productGrid').innerHTML=html||'<div class="empty">🌱 No products match your filters. Try a different search or category.</div>'}
function debouncedLoad(){clearTimeout(searchTimer);searchTimer=setTimeout(()=>loadProducts(),250)}
function clearFilters(){$('#search').value='';$('#categoryFilter').value='';$('#sort').value='newest';$('#availability').value='';loadProducts()}
function chooseCategory(name){$('#categoryFilter').value=name;$('#shop').scrollIntoView({behavior:'smooth'});loadProducts()}
function persistCart(){localStorage.setItem('rpaf_cart',JSON.stringify(cart));$('#cartCount').textContent=cart.reduce((s,x)=>s+x.quantity,0)}
function addCart(id){const p=products.find(x=>x._id===id);if(!p)return;const line=cart.find(x=>x.productId===id);if(line){if(line.quantity>=p.inventory)return toast('No more stock available.');line.quantity++}else cart.push({productId:id,quantity:1});persistCart();toast('Added to your cart 🌿')}
function wish(id){wishlist=wishlist.includes(id)?wishlist.filter(x=>x!==id):[...wishlist,id];localStorage.setItem('rpaf_wish',JSON.stringify(wishlist));renderProducts();toast(wishlist.includes(id)?'Added to wishlist':'Removed from wishlist')}
function openModal(title,html){$('#modalTitle').textContent=title;$('#modalBody').innerHTML=html;$('#modal').classList.add('open')}
function closeModal(){$('#modal').classList.remove('open')}
$('#modal').addEventListener('click',e=>{if(e.target===$('#modal'))closeModal()});
async function details(slug){try{const d=await api('/api/products/'+encodeURIComponent(slug)),p=d.item;openModal(p.name,\`<div class="aboutgrid"><img src="\${esc(imgSrc(p))}" alt="\${esc(p.name)}"><div><p class="muted">\${esc(p.category)} · \${esc(p.sku)}</p><h2>\${money(p.price)} <small>\${esc(p.unit)}</small></h2><p>\${esc(p.description||'Product details will be updated soon.')}</p><p>Available stock: \${p.inventory}</p>\${p.ingredients?'<p><b>Ingredients:</b> '+esc(p.ingredients)+'</p>':''}\${p.storageInstructions?'<p><b>Storage:</b> '+esc(p.storageInstructions)+'</p>':''}\${p.allergens?'<p><b>Allergen information:</b> '+esc(p.allergens)+'</p>':''}<button class="btn primary" onclick="addCart('\${p._id}');closeModal()">Add to cart</button></div></div>\`)}catch(e){toast(e.message)}}
async function openCart(){const ids=cart.map(x=>x.productId);let items=[];try{const d=await api('/api/products?limit=48');items=d.items}catch{}cart=cart.filter(x=>items.some(p=>p._id===x.productId));persistCart();const rows=cart.map(c=>{const p=items.find(x=>x._id===c.productId);return p?\`<div style="display:flex;gap:12px;align-items:center;padding:12px 0;border-bottom:1px solid #dce5d9"><img src="\${esc(imgSrc(p))}" style="width:65px;height:65px;object-fit:cover;border-radius:14px"><div style="flex:1"><b>\${esc(p.name)}</b><div class="muted">\${money(p.price)} · \${esc(p.unit)}</div><div style="display:flex;gap:8px;align-items:center;margin-top:8px"><button class="pill" onclick="changeQty('\${p._id}',-1)">−</button>\${c.quantity}<button class="pill" onclick="changeQty('\${p._id}',1,\${p.inventory})">+</button><button class="pill" onclick="removeCart('\${p._id}')">Remove</button></div></div><b>\${money(p.price*c.quantity)}</b></div>\`:''}).join('');const total=cart.reduce((s,c)=>s+(items.find(p=>p._id===c.productId)?.price||0)*c.quantity,0);openModal('Your shopping cart',\`\${rows||'<p class="muted">Your cart is waiting for something lovely.</p>'}<div style="padding:20px 0"><div style="display:flex;justify-content:space-between;font-size:20px"><b>Estimated subtotal</b><b>\${money(total)}</b></div><p class="muted" style="font-size:12px">Final shipping, tax, stock, and price are confirmed by the server at checkout.</p><button class="btn primary" style="width:100%" \${cart.length?'':'disabled'} onclick="checkout()">Continue to checkout →</button><button class="btn" style="width:100%;margin-top:10px" onclick="closeModal()">Continue shopping</button></div>\`)}
function changeQty(id,d,max=999){const x=cart.find(c=>c.productId===id);if(!x)return;x.quantity=Math.max(1,Math.min(max,x.quantity+d));persistCart();openCart()}
function removeCart(id){cart=cart.filter(c=>c.productId!==id);persistCart();openCart()}
async function checkout(){const cfg=await api('/api/config');if(!cart.length)return;openModal('Delivery & checkout',\`<p class="muted">Enter your delivery details. Prices and stock are recalculated securely on the server.</p><form id="checkoutForm"><div class="formgrid"><input name="name" placeholder="Full name" required maxlength="120"><input name="email" type="email" placeholder="Email" required><input name="phone" placeholder="Mobile number" required><input name="pin" placeholder="6-digit PIN code" pattern="[0-9]{6}" required></div><input name="address" placeholder="Address line" required><div class="formgrid"><input name="city" placeholder="City" required><input name="state" placeholder="State" required></div><textarea name="instructions" placeholder="Delivery instructions (optional)" style="width:100%;padding:12px;border-radius:12px;border:1px solid #ddd"></textarea><div style="margin:15px 0"><label><input type="radio" name="paymentMethod" value="razorpay" checked \${cfg.razorpayKeyId?'':'disabled'}> Online payment \${cfg.razorpayKeyId?'(Razorpay)':'(not configured)'}</label><br><label><input type="radio" name="paymentMethod" value="cod" \${cfg.razorpayKeyId?'':'checked'}> Cash on Delivery \${'enabled only when configured'}</label></div><button class="btn primary" type="submit" style="width:100%">Validate & place order →</button></form><p class="muted" style="font-size:11px">Do not close the page while payment verification is in progress.</p>\`);$('#checkoutForm').onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target),customer=Object.fromEntries(f.entries()),items=cart.map(x=>({productId:x.productId,quantity:x.quantity})),paymentMethod=customer.paymentMethod;try{const d=await api('/api/orders',{method:'POST',body:JSON.stringify({customer,items,paymentMethod})});if(paymentMethod==='cod'){cart=[];persistCart();openModal('Order placed 🎉',\`<p>Your order number is <b>\${esc(d.order.orderNumber)}</b>.</p><p>Payment is due on delivery.</p><button class="btn primary" onclick="closeModal()">Continue shopping</button>\`);return}if(!window.Razorpay)throw new Error('Razorpay checkout did not load. No payment has been completed. Contact support with your order number '+d.order.orderNumber);const rz=new Razorpay({key:d.razorpay.keyId,order_id:d.razorpay.orderId,amount:d.razorpay.amount,currency:d.razorpay.currency,name:'RP Agro Food',description:'Order '+d.order.orderNumber,prefill:{name:customer.name,email:customer.email,contact:customer.phone},handler:async response=>{try{const v=await api('/api/payments/razorpay/verify',{method:'POST',body:JSON.stringify(response)});cart=[];persistCart();openModal('Payment verified ✓',\`<p>Thank you. Your order <b>\${esc(v.order.orderNumber)}</b> is confirmed.</p><p>Payment status: \${esc(v.order.paymentStatus)}</p><button class="btn primary" onclick="closeModal()">Continue shopping</button>\`)}catch(err){openModal('Payment verification pending',\`<p>\${esc(err.message)}</p><p>Keep this order number for support: <b>\${esc(d.order.orderNumber)}</b></p><button class="btn" onclick="closeModal()">Close</button>\`)}} ,modal:{ondismiss:()=>toast('Checkout closed. Payment may still be pending; check your order status.')}});rz.open()}catch(err){toast(err.message)}}}
async function account(){openModal('Your account',\`<div class="formbox"><div style="display:flex;gap:8px;margin-bottom:15px"><button class="btn" type="button" onclick="accountForm('login')">Sign in</button><button class="btn" type="button" onclick="accountForm('register')">Create account</button></div><div id="accountInner"></div></div>\`);accountForm('login')}
function accountForm(mode){$('#accountInner').innerHTML=\`<form id="accountForm">\${mode==='register'?'<input name="name" placeholder="Full name" required>':''}<input name="email" type="email" placeholder="Email address" required><input name="phone" placeholder="Phone (optional)">\${mode==='register'?'<p class="muted" style="font-size:12px">Use a password of at least 10 characters.</p>':''}<input name="password" type="password" placeholder="Password (10+ characters)" minlength="10" required><button class="btn primary" style="width:100%">\${mode==='login'?'Sign in':'Create account'}</button></form><p class="muted" style="font-size:12px">Order history is available after sign-in.</p>\`;$('#accountForm').onsubmit=async e=>{e.preventDefault();const b=Object.fromEntries(new FormData(e.target).entries());try{const d=await api('/api/auth/'+(mode==='login'?'login':'register'),{method:'POST',body:JSON.stringify(b)});openModal('Welcome, '+d.user.name,\`<p>You are signed in as \${esc(d.user.email)}.</p><button class="btn primary" onclick="showOrders()">View my orders</button><button class="btn" onclick="logout()" style="margin-left:8px">Sign out</button>\`)}catch(err){toast(err.message)}}}
async function showOrders(){try{const d=await api('/api/account/orders');openModal('Your orders',d.items.map(o=>\`<div style="padding:12px 0;border-bottom:1px solid #ddd"><b>\${esc(o.orderNumber)}</b> · \${money(o.total)}<p>\${esc(o.orderStatus)} / \${esc(o.paymentStatus)}</p></div>\`).join('')||'<p>No orders yet.</p>')}catch(e){toast(e.message)}}
async function logout(){await api('/api/auth/logout',{method:'POST',body:'{}'});toast('Signed out');closeModal()}
function policy(title,text){openModal(title,\`<p>\${esc(text)}</p><button class="btn primary" onclick="closeModal()">Close</button>\`)}
async function sendForm(form,url){const b=Object.fromEntries(new FormData(form).entries());try{const d=await api(url,{method:'POST',body:JSON.stringify(b)});form.reset();toast(d.message||'Submitted successfully.')}catch(e){toast(e.message)}}
$('#enquiryForm').addEventListener('submit',e=>{e.preventDefault();sendForm(e.currentTarget,'/api/enquiries')});
$('#wholesaleForm').addEventListener('submit',e=>{e.preventDefault();sendForm(e.currentTarget,'/api/wholesale-enquiries')});
$('#year').textContent=new Date().getFullYear();persistCart();loadCategories();loadProducts();
</script></body></html>`;
app.get("/", (req, res) => res.type("html").send(homeHtml));
app.get("/shop", (req, res) => res.redirect(302, "/#shop"));
app.get("/robots.txt", (req, res) => res.type("text").send("User-agent: *\nAllow: /\n"));
app.use((req, res) => req.path.startsWith("/api/") ? fail(res, 404, "API endpoint not found.") : res.status(404).type("html").send("<h1>Page not found</h1><p><a href='/'>Return to RP Agro Food</a></p>"));
app.use((err, req, res, next) => {
  const status = err.status || (err.name === "ValidationError" ? 400 : 500);
  console.error("[RP Agro Food]", status, clean(err.message, 300));
  if (res.headersSent) return next(err);
  res.status(status).json({ ok: false, error: status >= 500 ? "The service is temporarily unavailable. Please try again later." : err.message });
});
if (require.main === module) {
  app.listen(PORT, () => console.log(`RP Agro Food running on port ${PORT}`));
}
module.exports = app;
