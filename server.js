import { createServer as createHttpServer } from "node:http";
import { createHash, randomBytes, scryptSync, timingSafeEqual, randomUUID } from "node:crypto";
import { mkdirSync, readFileSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { DatabaseSync } from "node:sqlite";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";

const ROOT = dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = join(ROOT, "public");
const SESSION_COOKIE = "anucho_session";
const SESSION_HOURS = 12;
const REMEMBER_DAYS = 30;
const CHALLENGE_TTL = 5 * 60 * 1000;
const PASSWORD_BYTES = 64;
const SCRYPT_OPTIONS = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const MAX_JSON_BYTES = 1024 * 1024;
const STATUS_VALUES = new Set(["active", "in_review", "pending", "filed", "granted", "expiring", "expired", "rejected"]);
const USER_ROLES = new Set(["owner", "editor", "reviewer"]);

class ApiError extends Error {
  constructor(status, message, headers = {}) {
    super(message);
    this.status = status;
    this.headers = headers;
  }
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hash(value) {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalEmail(value) {
  if (typeof value !== "string") {
    throw new ApiError(400, "Enter a valid email address.");
  }
  const result = value.trim().toLowerCase();
  if (result.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(result)) {
    throw new ApiError(400, "Enter a valid email address.");
  }
  return result;
}

function canonicalPhone(value) {
  if (typeof value !== "string") {
    throw new ApiError(400, "Enter a phone number in international format, such as +14155550123.");
  }
  const result = value.trim().replace(/[\s().-]/g, "");
  if (!/^\+[1-9]\d{6,14}$/.test(result)) {
    throw new ApiError(400, "Enter a phone number in international format, such as +14155550123.");
  }
  return result;
}

function contactFromIdentifier(identifier) {
  if (typeof identifier !== "string" || !identifier.trim()) {
    throw new ApiError(400, "Enter your email address or phone number.");
  }
  const value = identifier.trim();
  if (value.includes("@")) {
    return { email: canonicalEmail(value), phone: null };
  }
  return { email: null, phone: canonicalPhone(value) };
}

function optionalText(value, label, maximum) {
  if (value == null || value === "") {
    return "";
  }
  if (typeof value !== "string") {
    throw new ApiError(400, `${label} must be text.`);
  }
  const result = value.trim();
  if (result.length > maximum) {
    throw new ApiError(400, `${label} must be ${maximum} characters or fewer.`);
  }
  return result;
}

function requiredText(value, label, maximum) {
  const result = optionalText(value, label, maximum);
  if (!result) {
    throw new ApiError(400, `${label} is required.`);
  }
  return result;
}

function validatePassword(password) {
  if (typeof password !== "string" || password.length < 12 || Buffer.byteLength(password, "utf8") > 1024) {
    throw new ApiError(400, "Use a password with at least 12 characters.");
  }
  return password;
}

function passwordHash(password) {
  const salt = randomBytes(16);
  const derived = scryptSync(password, salt, PASSWORD_BYTES, SCRYPT_OPTIONS);
  return `scrypt$${salt.toString("base64url")}$${derived.toString("base64url")}`;
}

const dummyPasswordHash = passwordHash(randomBytes(32).toString("base64url"));

function passwordMatches(password, savedHash) {
  if (typeof password !== "string" || Buffer.byteLength(password, "utf8") > 1024) {
    return false;
  }
  const parts = typeof savedHash === "string" ? savedHash.split("$") : [];
  const validFormat = parts.length === 3 && parts[0] === "scrypt";
  const salt = validFormat ? Buffer.from(parts[1], "base64url") : Buffer.alloc(16);
  const expected = validFormat ? Buffer.from(parts[2], "base64url") : Buffer.alloc(PASSWORD_BYTES);
  const candidate = scryptSync(password, salt, PASSWORD_BYTES, SCRYPT_OPTIONS);
  return validFormat && expected.length === candidate.length && timingSafeEqual(candidate, expected);
}

function createDatabase(databasePath) {
  mkdirSync(dirname(databasePath), { recursive: true });
  const database = new DatabaseSync(databasePath, { timeout: 5000 });
  database.exec(`
    PRAGMA foreign_keys = ON;
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = NORMAL;
    PRAGMA busy_timeout = 5000;

    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT COLLATE NOCASE UNIQUE,
      phone TEXT UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'editor' CHECK (role IN ('owner', 'editor', 'reviewer')),
      must_change_password INTEGER NOT NULL DEFAULT 0 CHECK (must_change_password IN (0, 1)),
      created_at TEXT NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      reauthenticated_at INTEGER NOT NULL
    ) STRICT;
    CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);

    CREATE TABLE IF NOT EXISTS passkeys (
      credential_id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      public_key BLOB NOT NULL,
      counter INTEGER NOT NULL DEFAULT 0,
      transports TEXT NOT NULL DEFAULT '[]',
      device_type TEXT NOT NULL DEFAULT '',
      backed_up INTEGER NOT NULL DEFAULT 0 CHECK (backed_up IN (0, 1)),
      name TEXT NOT NULL,
      created_at TEXT NOT NULL
    ) STRICT;
    CREATE INDEX IF NOT EXISTS passkeys_user ON passkeys(user_id);

    CREATE TABLE IF NOT EXISTS rate_limits (
      rate_key TEXT PRIMARY KEY,
      window_started_at INTEGER NOT NULL,
      attempts INTEGER NOT NULL,
      locked_until INTEGER NOT NULL DEFAULT 0
    ) STRICT;

    CREATE TABLE IF NOT EXISTS patents (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      patent_number TEXT NOT NULL DEFAULT '',
      owner TEXT NOT NULL DEFAULT '',
      category TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('active', 'in_review', 'pending', 'filed', 'granted', 'expiring', 'expired', 'rejected')),
      filing_date TEXT NOT NULL DEFAULT '',
      renewal_date TEXT NOT NULL DEFAULT '',
      estimated_value REAL NOT NULL DEFAULT 0 CHECK (estimated_value >= 0),
      description TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    ) STRICT;
    CREATE INDEX IF NOT EXISTS patents_updated ON patents(updated_at DESC);
    CREATE INDEX IF NOT EXISTS patents_status ON patents(status);

    CREATE TABLE IF NOT EXISTS products (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      category TEXT NOT NULL DEFAULT '',
      description TEXT NOT NULL DEFAULT '',
      sku TEXT NOT NULL DEFAULT '',
      price_cents INTEGER NOT NULL DEFAULT 0 CHECK (price_cents >= 0),
      stock_quantity INTEGER NOT NULL DEFAULT 0 CHECK (stock_quantity >= 0),
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    ) STRICT;
    CREATE INDEX IF NOT EXISTS products_name ON products(name);

    CREATE TABLE IF NOT EXISTS product_patents (
      product_id TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
      patent_id TEXT NOT NULL REFERENCES patents(id) ON DELETE CASCADE,
      PRIMARY KEY (product_id, patent_id)
    ) STRICT;

    CREATE TABLE IF NOT EXISTS suppliers (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      service TEXT NOT NULL DEFAULT '',
      email TEXT NOT NULL DEFAULT '',
      phone TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'in_review', 'inactive')),
      notes TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    ) STRICT;
    CREATE INDEX IF NOT EXISTS suppliers_name ON suppliers(name);

    CREATE TABLE IF NOT EXISTS collections (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      is_public INTEGER NOT NULL DEFAULT 0 CHECK (is_public IN (0, 1)),
      patent_ids TEXT NOT NULL DEFAULT '[]',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS sales (
      id TEXT PRIMARY KEY,
      receipt_number TEXT NOT NULL UNIQUE,
      cashier_id TEXT NOT NULL REFERENCES users(id),
      customer_name TEXT NOT NULL DEFAULT '',
      items TEXT NOT NULL,
      subtotal_cents INTEGER NOT NULL CHECK (subtotal_cents >= 0),
      tax_cents INTEGER NOT NULL CHECK (tax_cents >= 0),
      total_cents INTEGER NOT NULL CHECK (total_cents >= 0),
      amount_received_cents INTEGER NOT NULL CHECK (amount_received_cents >= 0),
      change_cents INTEGER NOT NULL CHECK (change_cents >= 0),
      payment_method TEXT NOT NULL CHECK (payment_method IN ('cash', 'card', 'other')),
      status TEXT NOT NULL DEFAULT 'completed' CHECK (status IN ('completed', 'refunded')),
      refunded_at TEXT NOT NULL DEFAULT '',
      refunded_by TEXT REFERENCES users(id),
      refund_reason TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL
    ) STRICT;
    CREATE INDEX IF NOT EXISTS sales_created ON sales(created_at DESC);

    CREATE TABLE IF NOT EXISTS settings (
      setting_key TEXT PRIMARY KEY,
      setting_value TEXT NOT NULL
    ) STRICT;
    INSERT OR IGNORE INTO settings (setting_key, setting_value) VALUES
      ('workspaceName', '"ANUCHO"'),
      ('currency', '"USD"'),
      ('timezone', '"UTC"'),
      ('taxRate', '0');
  `);
  const productColumns = new Set(database.prepare("PRAGMA table_info(products)").all().map((column) => column.name));
  if (!productColumns.has("sku")) {
    database.exec("ALTER TABLE products ADD COLUMN sku TEXT NOT NULL DEFAULT ''");
  }
  if (!productColumns.has("price_cents")) {
    database.exec("ALTER TABLE products ADD COLUMN price_cents INTEGER NOT NULL DEFAULT 0 CHECK (price_cents >= 0)");
  }
  if (!productColumns.has("stock_quantity")) {
    database.exec("ALTER TABLE products ADD COLUMN stock_quantity INTEGER NOT NULL DEFAULT 0 CHECK (stock_quantity >= 0)");
  }
  const saleColumns = new Set(database.prepare("PRAGMA table_info(sales)").all().map((column) => column.name));
  if (!saleColumns.has("status")) {
    database.exec("ALTER TABLE sales ADD COLUMN status TEXT NOT NULL DEFAULT 'completed' CHECK (status IN ('completed', 'refunded'))");
  }
  if (!saleColumns.has("refunded_at")) {
    database.exec("ALTER TABLE sales ADD COLUMN refunded_at TEXT NOT NULL DEFAULT ''");
  }
  if (!saleColumns.has("refunded_by")) {
    database.exec("ALTER TABLE sales ADD COLUMN refunded_by TEXT REFERENCES users(id)");
  }
  if (!saleColumns.has("refund_reason")) {
    database.exec("ALTER TABLE sales ADD COLUMN refund_reason TEXT NOT NULL DEFAULT ''");
  }
  database.exec("CREATE UNIQUE INDEX IF NOT EXISTS products_sku_unique ON products(sku) WHERE sku != ''");
  return database;
}

function transact(database, callback) {
  database.exec("BEGIN IMMEDIATE");
  try {
    const result = callback();
    database.exec("COMMIT");
    return result;
  } catch (error) {
    try {
      database.exec("ROLLBACK");
    } catch (rollbackError) {
      throw new AggregateError([error, rollbackError], "The SQLite transaction and rollback both failed.");
    }
    throw error;
  }
}

function isConstraintError(error) {
  return error?.code?.startsWith("ERR_SQLITE_CONSTRAINT")
    || (typeof error?.errcode === "number" && (error.errcode & 0xff) === 19);
}

function rowUser(database, userId) {
  return database.prepare(`
    SELECT id, name, email, phone, role, must_change_password, created_at,
      (SELECT COUNT(*) FROM passkeys WHERE passkeys.user_id = users.id) AS passkey_count
    FROM users WHERE id = ?
  `).get(userId);
}

function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    phone: user.phone,
    role: user.role,
    mustChangePassword: Boolean(user.must_change_password),
    passkeyCount: Number(user.passkey_count),
    createdAt: user.created_at,
  };
}

function cookieToken(request) {
  const cookie = request.headers.cookie;
  if (typeof cookie !== "string") {
    return null;
  }
  for (const piece of cookie.split(";")) {
    const separator = piece.indexOf("=");
    if (separator > 0 && piece.slice(0, separator).trim() === SESSION_COOKIE) {
      try {
        return decodeURIComponent(piece.slice(separator + 1).trim());
      } catch {
        return null;
      }
    }
  }
  return null;
}

function cookieValue(token, maxAge, secure) {
  return `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure ? "; Secure" : ""}`;
}

function clearCookie(secure) {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure ? "; Secure" : ""}`;
}

function cleanChallenges(map, now) {
  for (const [key, challenge] of map) {
    if (challenge.expiresAt <= now) {
      map.delete(key);
    }
  }
}

function parseDate(value, label) {
  const date = optionalText(value, label, 10);
  if (!date) {
    return "";
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    throw new ApiError(400, `${label} must be a valid date.`);
  }
  const parsed = new Date(`${date}T00:00:00.000Z`);
  if (Number.isNaN(parsed.getTime()) || parsed.toISOString().slice(0, 10) !== date) {
    throw new ApiError(400, `${label} must be a valid date.`);
  }
  return date;
}

function canonicalStatus(value, permitted = STATUS_VALUES) {
  const status = requiredText(value, "Status", 32).toLowerCase().replace(/[\s-]+/g, "_");
  if (!permitted.has(status)) {
    throw new ApiError(400, "Choose a valid status.");
  }
  return status;
}

function finiteAmount(value, label, maximum = 1_000_000_000_000) {
  if (value == null || value === "") {
    return 0;
  }
  const amount = Number(value);
  if (!Number.isFinite(amount) || amount < 0 || amount > maximum) {
    throw new ApiError(400, `${label} must be a non-negative number.`);
  }
  return amount;
}

function priceInCents(value, label) {
  const amount = value == null || value === "" ? 0 : Number(value);
  if (!Number.isFinite(amount) || amount < 0 || amount > 999_999_999.99) {
    throw new ApiError(400, `${label} must be a non-negative amount.`);
  }
  const cents = Math.round(amount * 100);
  if (Math.abs(amount * 100 - cents) > 0.000001) {
    throw new ApiError(400, `${label} cannot have more than two decimal places.`);
  }
  return cents;
}

function stockCount(value, label) {
  const quantity = value == null || value === "" ? 0 : Number(value);
  if (!Number.isSafeInteger(quantity) || quantity < 0 || quantity > 1_000_000_000) {
    throw new ApiError(400, `${label} must be a non-negative whole number.`);
  }
  return quantity;
}

function parsePatent(row) {
  if (!row) {
    return null;
  }
  return {
    id: row.id,
    title: row.title,
    patentNumber: row.patent_number,
    owner: row.owner,
    category: row.category,
    status: row.status,
    filingDate: row.filing_date,
    renewalDate: row.renewal_date,
    estimatedValue: Number(row.estimated_value),
    description: row.description,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function parseProduct(database, row) {
  if (!row) {
    return null;
  }
  const patentIds = database.prepare("SELECT patent_id FROM product_patents WHERE product_id = ? ORDER BY patent_id").all(row.id);
  return {
    id: row.id,
    name: row.name,
    category: row.category,
    description: row.description,
    sku: row.sku,
    price: Number(row.price_cents) / 100,
    stockQuantity: Number(row.stock_quantity),
    patentIds: patentIds.map((patent) => patent.patent_id),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function parseSale(row) {
  if (!row) {
    return null;
  }
  return {
    id: row.id,
    receiptNumber: row.receipt_number,
    cashierId: row.cashier_id,
    customerName: row.customer_name,
    items: JSON.parse(row.items),
    subtotalCents: Number(row.subtotal_cents),
    taxCents: Number(row.tax_cents),
    totalCents: Number(row.total_cents),
    amountReceivedCents: Number(row.amount_received_cents),
    changeCents: Number(row.change_cents),
    paymentMethod: row.payment_method,
    status: row.status,
    refundedAt: row.refunded_at,
    refundedBy: row.refunded_by,
    refundReason: row.refund_reason,
    createdAt: row.created_at,
  };
}

function parseSupplier(row) {
  if (!row) {
    return null;
  }
  return {
    id: row.id,
    name: row.name,
    service: row.service,
    email: row.email,
    phone: row.phone,
    status: row.status,
    notes: row.notes,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function parseCollection(row) {
  if (!row) {
    return null;
  }
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    isPublic: Boolean(row.is_public),
    patentIds: JSON.parse(row.patent_ids),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function validatePatent(body, previous, defaultOwner) {
  const merged = { ...previous, ...body };
  const status = canonicalStatus(merged.status || "pending");
  const amount = finiteAmount(merged.estimatedValue, "Estimated value");
  return {
    title: requiredText(merged.title, "Patent title", 200),
    patentNumber: optionalText(merged.patentNumber, "Patent number", 80),
    owner: optionalText(merged.owner || defaultOwner, "Owner", 160),
    category: optionalText(merged.category, "Category", 100),
    status,
    filingDate: parseDate(merged.filingDate, "Filing date"),
    renewalDate: parseDate(merged.renewalDate, "Renewal date"),
    estimatedValue: amount,
    description: optionalText(merged.description, "Description", 5000),
  };
}

function validateProduct(body, previous) {
  const merged = { ...previous, ...body };
  const patentIds = merged.patentIds ?? [];
  if (!Array.isArray(patentIds) || patentIds.length > 100 || patentIds.some((id) => typeof id !== "string")) {
    throw new ApiError(400, "Patent links must be a list of patent IDs.");
  }
  if (new Set(patentIds).size !== patentIds.length) {
    throw new ApiError(400, "A patent can only be linked once.");
  }
  return {
    name: requiredText(merged.name, "Product name", 200),
    category: optionalText(merged.category, "Category", 100),
    description: optionalText(merged.description, "Description", 5000),
    sku: optionalText(merged.sku, "SKU", 64).toUpperCase(),
    priceCents: priceInCents(merged.price, "Price"),
    stockQuantity: stockCount(merged.stockQuantity, "Stock quantity"),
    patentIds,
  };
}

function validateSupplier(body, previous) {
  const merged = { ...previous, ...body };
  const status = canonicalStatus(merged.status || "active", new Set(["active", "in_review", "inactive"]));
  let email = optionalText(merged.email, "Supplier email", 254);
  if (email) {
    email = canonicalEmail(email);
  }
  let phone = optionalText(merged.phone, "Supplier phone", 32);
  if (phone) {
    phone = canonicalPhone(phone);
  }
  return {
    name: requiredText(merged.name, "Supplier name", 200),
    service: optionalText(merged.service, "Service", 120),
    email,
    phone,
    status,
    notes: optionalText(merged.notes, "Notes", 5000),
  };
}

function validateCollection(database, body, previous) {
  const merged = { ...previous, ...body };
  const patentIds = merged.patentIds ?? [];
  if (!Array.isArray(patentIds) || patentIds.length > 100 || patentIds.some((id) => typeof id !== "string")) {
    throw new ApiError(400, "Patent links must be a list of patent IDs.");
  }
  if (new Set(patentIds).size !== patentIds.length) {
    throw new ApiError(400, "A patent can only be linked once.");
  }
  for (const patentId of patentIds) {
    if (!database.prepare("SELECT 1 FROM patents WHERE id = ?").get(patentId)) {
      throw new ApiError(400, "A linked patent no longer exists. Refresh and try again.");
    }
  }
  if (typeof merged.isPublic !== "boolean") {
    throw new ApiError(400, "Choose whether this showroom collection is public.");
  }
  return {
    name: requiredText(merged.name, "Collection name", 200),
    description: optionalText(merged.description, "Description", 5000),
    isPublic: merged.isPublic,
    patentIds,
  };
}

function inputObject(value) {
  if (!isRecord(value)) {
    throw new ApiError(400, "Send a JSON object.");
  }
  return value;
}

function escapeCsv(value) {
  let result = String(value ?? "");
  if (/^[\s]*[=+\-@]/.test(result)) {
    result = `'${result}`;
  }
  return `"${result.replace(/"/g, '""')}"`;
}

function csvRow(values) {
  return `${values.map(escapeCsv).join(",")}\r\n`;
}

function verifyBodyShape(body, allowedKeys) {
  const unknownKey = Object.keys(body).find((key) => !allowedKeys.has(key));
  if (unknownKey) {
    throw new ApiError(400, `Unknown field: ${unknownKey}.`);
  }
}

export function createServer(options = {}) {
  const configuredOrigin = options.origin
    ?? process.env.ANUCHO_ORIGIN
    ?? process.env.RENDER_EXTERNAL_URL
    ?? "http://localhost:3000";
  let originUrl;
  try {
    originUrl = new URL(configuredOrigin);
  } catch {
    throw new Error("ANUCHO_ORIGIN must be a valid absolute URL.");
  }
  if (!["http:", "https:"].includes(originUrl.protocol) || originUrl.origin !== configuredOrigin || originUrl.pathname !== "/") {
    throw new Error("ANUCHO_ORIGIN must be an origin such as https://anucho.example.com without a path.");
  }
  if (process.env.NODE_ENV === "production" && originUrl.protocol !== "https:") {
    throw new Error("Set ANUCHO_ORIGIN to an HTTPS address for production.");
  }

  const relyingPartyId = process.env.ANUCHO_RP_ID ?? originUrl.hostname;
  const secureCookie = originUrl.protocol === "https:";
  const port = options.port ?? Number(process.env.PORT ?? originUrl.port ?? 3000);
  const host = options.host ?? process.env.ANUCHO_HOST ?? "localhost";
  const databasePath = resolve(options.databasePath ?? process.env.ANUCHO_DB_PATH ?? join(ROOT, "data", "anucho.db"));
  const database = createDatabase(databasePath);
  const registrationChallenges = new Map();
  const authenticationChallenges = new Map();
  const eventClients = new Set();
  let lastRateLimitCleanup = 0;

  function respond(response, status, body, headers = {}) {
    response.writeHead(status, { "Content-Type": "application/json; charset=utf-8", ...headers });
    response.end(JSON.stringify(body));
  }

  function secureHeaders(request, response) {
    response.setHeader("Cache-Control", "no-store");
    response.setHeader("X-Content-Type-Options", "nosniff");
    response.setHeader("X-Frame-Options", "DENY");
    response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    response.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    response.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'",
    );
    if (secureCookie) {
      response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    }
    if (request.headers.host?.toLowerCase() !== originUrl.host.toLowerCase()) {
      throw new ApiError(400, "This request host does not match the configured ANUCHO origin.");
    }
  }

  function assertSameOrigin(request) {
    if (request.headers.origin !== configuredOrigin) {
      throw new ApiError(403, "The request origin could not be verified.");
    }
    if (request.headers["content-type"]?.split(";", 1)[0].trim().toLowerCase() !== "application/json") {
      throw new ApiError(415, "Send this request using application/json.");
    }
  }

  async function readJson(request) {
    const length = Number(request.headers["content-length"] || 0);
    if (length > MAX_JSON_BYTES) {
      throw new ApiError(413, "The request body is too large.");
    }
    const chunks = [];
    let size = 0;
    for await (const chunk of request) {
      size += chunk.length;
      if (size > MAX_JSON_BYTES) {
        throw new ApiError(413, "The request body is too large.");
      }
      chunks.push(chunk);
    }
    try {
      return inputObject(JSON.parse(Buffer.concat(chunks).toString("utf8")));
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }
      throw new ApiError(400, "Send a valid JSON request body.");
    }
  }

  function sessionFor(request) {
    const token = cookieToken(request);
    if (!token || token.length > 256) {
      return null;
    }
    const tokenHash = hash(token);
    const session = database.prepare(`
      SELECT sessions.token_hash, sessions.expires_at, sessions.reauthenticated_at,
        users.id, users.name, users.email, users.phone, users.role, users.must_change_password, users.created_at
      FROM sessions JOIN users ON users.id = sessions.user_id
      WHERE sessions.token_hash = ?
    `).get(tokenHash);
    if (!session) {
      return null;
    }
    if (session.expires_at <= Date.now()) {
      database.prepare("DELETE FROM sessions WHERE token_hash = ?").run(tokenHash);
      return null;
    }
    return session;
  }

  function requireSession(request, pathname) {
    const session = sessionFor(request);
    if (!session) {
      throw new ApiError(401, "Please sign in again.");
    }
    if (
      session.must_change_password
      && !["/api/auth/change-password", "/api/auth/logout", "/api/me"].includes(pathname)
    ) {
      throw new ApiError(403, "Change your temporary password before continuing.");
    }
    return session;
  }

  function requireWriter(session) {
    if (!["owner", "editor"].includes(session.role)) {
      throw new ApiError(403, "You do not have permission to change workspace records.");
    }
  }

  function requireOwner(session) {
    if (session.role !== "owner") {
      throw new ApiError(403, "Only the workspace owner can perform this action.");
    }
  }

  function closeEventClient(client) {
    clearInterval(client.heartbeat);
    eventClients.delete(client);
  }

  function publishWorkspaceChange(resources, excludedTokenHash) {
    const data = JSON.stringify({ resources });
    for (const client of eventClients) {
      if (client.tokenHash === excludedTokenHash) {
        continue;
      }
      if (client.response.destroyed || client.response.writableLength > 64 * 1024) {
        closeEventClient(client);
        client.response.destroy();
        continue;
      }
      client.response.write(`event: workspace-change\ndata: ${data}\n\n`);
    }
  }

  function changedResources(method, pathname) {
    if (!["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
      return [];
    }
    if (/^\/api\/sales(?:\/|$)/.test(pathname)) {
      return ["sales", "products"];
    }
    const match = pathname.match(/^\/api\/(patents|products|suppliers|collections|team|settings)(?:\/|$)/);
    return match ? [match[1]] : [];
  }

  function requireRecentAuthentication(session) {
    if (session.reauthenticated_at < Date.now() - CHALLENGE_TTL) {
      throw new ApiError(401, "Confirm your password before managing passkeys.", { "X-Reauthentication-Required": "true" });
    }
  }

  function createSession(response, userId, rememberMe = false) {
    const token = randomBytes(32).toString("base64url");
    const now = Date.now();
    const maxAge = rememberMe ? REMEMBER_DAYS * 24 * 60 * 60 : SESSION_HOURS * 60 * 60;
    database.prepare(`
      INSERT INTO sessions (token_hash, user_id, created_at, expires_at, reauthenticated_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(hash(token), userId, now, now + maxAge * 1000, now);
    response.setHeader("Set-Cookie", cookieValue(token, maxAge, secureCookie));
    return publicUser(rowUser(database, userId));
  }

  function clientAddress(request) {
    return request.socket.remoteAddress || "unknown";
  }

  function rateKey(purpose, request, identity = "") {
    return hash(`${purpose}\u0000${clientAddress(request)}\u0000${identity}`);
  }

  function enforceRateLimit(key, limit, windowMs) {
    const now = Date.now();
    if (now - lastRateLimitCleanup > 60 * 1000) {
      database.prepare("DELETE FROM rate_limits WHERE MAX(window_started_at, locked_until) < ?")
        .run(now - 24 * 60 * 60 * 1000);
      database.prepare("DELETE FROM sessions WHERE expires_at <= ?").run(now);
      lastRateLimitCleanup = now;
    }
    const saved = database.prepare("SELECT * FROM rate_limits WHERE rate_key = ?").get(key);
    if (saved?.locked_until > now) {
      throw new ApiError(429, "Too many attempts. Please wait before trying again.", {
        "Retry-After": String(Math.ceil((saved.locked_until - now) / 1000)),
      });
    }
    if (!saved || now - saved.window_started_at >= windowMs) {
      database.prepare(`
        INSERT INTO rate_limits (rate_key, window_started_at, attempts, locked_until)
        VALUES (?, ?, 1, 0)
        ON CONFLICT(rate_key) DO UPDATE SET
          window_started_at = excluded.window_started_at, attempts = 1, locked_until = 0
      `).run(key, now);
    } else {
      const attempts = saved.attempts + 1;
      const lockedUntil = attempts > limit ? now + windowMs : 0;
      database.prepare(`
        UPDATE rate_limits SET attempts = ?, locked_until = ? WHERE rate_key = ?
      `).run(attempts, lockedUntil, key);
      if (lockedUntil) {
        throw new ApiError(429, "Too many attempts. Please wait before trying again.", {
          "Retry-After": String(Math.ceil(windowMs / 1000)),
        });
      }
    }
  }

  function resetRateLimit(key) {
    database.prepare("DELETE FROM rate_limits WHERE rate_key = ?").run(key);
  }

  function parseLoginIdentifier(identifier) {
    const value = typeof identifier === "string" ? identifier.trim() : "";
    if (value.length > 254 || !value) {
      return null;
    }
    if (value.includes("@")) {
      return { email: value.toLowerCase(), phone: null };
    }
    const digits = value.replace(/[\s().-]/g, "");
    if (!/^\+[1-9]\d{6,14}$/.test(digits)) {
      return null;
    }
    return { email: null, phone: digits };
  }

  function listPatents(query) {
    const search = query.trim().slice(0, 100);
    const rows = search
      ? database.prepare(`
        SELECT * FROM patents
        WHERE title LIKE ? ESCAPE '\\' OR patent_number LIKE ? ESCAPE '\\'
          OR owner LIKE ? ESCAPE '\\' OR category LIKE ? ESCAPE '\\' OR status LIKE ? ESCAPE '\\'
        ORDER BY updated_at DESC LIMIT 200
      `).all(...Array(5).fill(`%${search.replace(/[\\%_]/g, "\\$&")}%`))
      : database.prepare("SELECT * FROM patents ORDER BY updated_at DESC LIMIT 200").all();
    return rows.map(parsePatent);
  }

  function listProducts(query) {
    const search = query.trim().slice(0, 100);
    const rows = search
      ? database.prepare(`
        SELECT * FROM products
        WHERE name LIKE ? ESCAPE '\\' OR category LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\'
        ORDER BY updated_at DESC LIMIT 200
      `).all(...Array(3).fill(`%${search.replace(/[\\%_]/g, "\\$&")}%`))
      : database.prepare("SELECT * FROM products ORDER BY updated_at DESC LIMIT 200").all();
    return rows.map((row) => parseProduct(database, row));
  }

  function currentStoreDate() {
    const setting = database.prepare("SELECT setting_value FROM settings WHERE setting_key = 'timezone'").get();
    const timezone = setting ? JSON.parse(setting.setting_value) : "UTC";
    const parts = new Intl.DateTimeFormat("en-US", {
      timeZone: timezone,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
    }).formatToParts(new Date());
    const values = Object.fromEntries(parts.map((part) => [part.type, part.value]));
    return `${values.year}-${values.month}-${values.day}`;
  }

  function listSuppliers(query) {
    const search = query.trim().slice(0, 100);
    const rows = search
      ? database.prepare(`
        SELECT * FROM suppliers
        WHERE name LIKE ? ESCAPE '\\' OR service LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\'
        ORDER BY updated_at DESC LIMIT 200
      `).all(...Array(3).fill(`%${search.replace(/[\\%_]/g, "\\$&")}%`))
      : database.prepare("SELECT * FROM suppliers ORDER BY updated_at DESC LIMIT 200").all();
    return rows.map(parseSupplier);
  }

  function listCollections(isPublic = false) {
    const rows = database.prepare(`
      SELECT * FROM collections ${isPublic ? "WHERE is_public = 1" : ""}
      ORDER BY updated_at DESC LIMIT 200
    `).all();
    return rows.map(parseCollection);
  }

  function writePatent(body, userId, previous = null) {
    const fields = validatePatent(body, previous, rowUser(database, userId).name);
    const now = new Date().toISOString();
    const id = previous?.id ?? randomUUID();
    if (previous) {
      database.prepare(`
        UPDATE patents SET title = ?, patent_number = ?, owner = ?, category = ?, status = ?,
          filing_date = ?, renewal_date = ?, estimated_value = ?, description = ?, updated_at = ?
        WHERE id = ?
      `).run(
        fields.title, fields.patentNumber, fields.owner, fields.category, fields.status,
        fields.filingDate, fields.renewalDate, fields.estimatedValue, fields.description, now, id,
      );
    } else {
      database.prepare(`
        INSERT INTO patents
          (id, title, patent_number, owner, category, status, filing_date, renewal_date, estimated_value, description, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        id, fields.title, fields.patentNumber, fields.owner, fields.category, fields.status,
        fields.filingDate, fields.renewalDate, fields.estimatedValue, fields.description, now, now,
      );
    }
    return parsePatent(database.prepare("SELECT * FROM patents WHERE id = ?").get(id));
  }

  function writeProduct(body, previous = null) {
    const fields = validateProduct(body, previous);
    for (const patentId of fields.patentIds) {
      if (!database.prepare("SELECT 1 FROM patents WHERE id = ?").get(patentId)) {
        throw new ApiError(400, "A linked patent no longer exists. Refresh and try again.");
      }
    }
    const now = new Date().toISOString();
    const id = previous?.id ?? randomUUID();
    try {
      transact(database, () => {
        if (previous) {
          database.prepare(`UPDATE products SET name = ?, category = ?, description = ?, sku = ?,
            price_cents = ?, stock_quantity = ?, updated_at = ? WHERE id = ?`)
            .run(fields.name, fields.category, fields.description, fields.sku, fields.priceCents, fields.stockQuantity, now, id);
        } else {
          database.prepare(`INSERT INTO products
            (id, name, category, description, sku, price_cents, stock_quantity, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
            .run(id, fields.name, fields.category, fields.description, fields.sku, fields.priceCents, fields.stockQuantity, now, now);
        }
        database.prepare("DELETE FROM product_patents WHERE product_id = ?").run(id);
        const link = database.prepare("INSERT INTO product_patents (product_id, patent_id) VALUES (?, ?)");
        for (const patentId of fields.patentIds) {
          link.run(id, patentId);
        }
      });
    } catch (error) {
      if (isConstraintError(error) && String(error.message).includes("products.sku")) {
        throw new ApiError(409, "That SKU is already assigned to another product.");
      }
      throw error;
    }
    return parseProduct(database, database.prepare("SELECT * FROM products WHERE id = ?").get(id));
  }

  function writeSupplier(body, previous = null) {
    const fields = validateSupplier(body, previous);
    const now = new Date().toISOString();
    const id = previous?.id ?? randomUUID();
    if (previous) {
      database.prepare("UPDATE suppliers SET name = ?, service = ?, email = ?, phone = ?, status = ?, notes = ?, updated_at = ? WHERE id = ?")
        .run(fields.name, fields.service, fields.email, fields.phone, fields.status, fields.notes, now, id);
    } else {
      database.prepare(`
        INSERT INTO suppliers (id, name, service, email, phone, status, notes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(id, fields.name, fields.service, fields.email, fields.phone, fields.status, fields.notes, now, now);
    }
    return parseSupplier(database.prepare("SELECT * FROM suppliers WHERE id = ?").get(id));
  }

  function writeCollection(body, previous = null) {
    const fields = validateCollection(database, body, previous);
    const now = new Date().toISOString();
    const id = previous?.id ?? randomUUID();
    const values = JSON.stringify(fields.patentIds);
    if (previous) {
      database.prepare("UPDATE collections SET name = ?, description = ?, is_public = ?, patent_ids = ?, updated_at = ? WHERE id = ?")
        .run(fields.name, fields.description, Number(fields.isPublic), values, now, id);
    } else {
      database.prepare(`
        INSERT INTO collections (id, name, description, is_public, patent_ids, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(id, fields.name, fields.description, Number(fields.isPublic), values, now, now);
    }
    return parseCollection(database.prepare("SELECT * FROM collections WHERE id = ?").get(id));
  }

  function checkMethod(request, methods) {
    if (!methods.includes(request.method)) {
      throw new ApiError(405, "This request method is not supported.", { Allow: methods.join(", ") });
    }
  }

  async function handle(request, response) {
    secureHeaders(request, response);
    const url = new URL(request.url, configuredOrigin);
    const pathname = url.pathname;
    const method = request.method;
    if (method === "OPTIONS") {
      response.writeHead(204, { Allow: "GET, HEAD, POST, PATCH, PUT, DELETE, OPTIONS" });
      response.end();
      return;
    }

    if (method === "GET" && pathname === "/api/healthz") {
      respond(response, 200, { ok: true });
      return;
    }
    if (method === "GET" && pathname === "/api/setup-status") {
      respond(response, 200, { setupComplete: Boolean(database.prepare("SELECT 1 FROM users LIMIT 1").get()) });
      return;
    }
    if (method === "GET" && pathname === "/api/showroom") {
      const collections = listCollections(true).map((collection) => ({
        name: collection.name,
        description: collection.description,
        patents: collection.patentIds
          .map((id) => database.prepare(`
            SELECT title, patent_number, category FROM patents WHERE id = ?
          `).get(id))
          .filter(Boolean),
      }));
      respond(response, 200, { collections });
      return;
    }
    const publicFiles = { "/": ["index.html", "text/html"], "/ANUCHO.html": ["index.html", "text/html"], "/app.js": ["app.js", "text/javascript"] };
    if (method === "GET" && publicFiles[pathname]) {
      const [filename, contentType] = publicFiles[pathname];
      const contents = readFileSync(join(WEB_ROOT, filename));
      response.writeHead(200, {
        "Content-Type": `${contentType}; charset=utf-8`,
        "Content-Length": contents.length,
      });
      response.end(contents);
      return;
    }

    if (method !== "GET" && method !== "HEAD") {
      assertSameOrigin(request);
    }

    if (pathname === "/api/setup" && method === "POST") {
      if (database.prepare("SELECT 1 FROM users LIMIT 1").get()) {
        throw new ApiError(409, "This workspace already has an owner. Sign in instead.");
      }
      const body = await readJson(request);
      verifyBodyShape(body, new Set(["name", "identifier", "password"]));
      enforceRateLimit(rateKey("setup", request), 5, 60 * 60 * 1000);
      const name = requiredText(body.name, "Your name", 120);
      const contact = contactFromIdentifier(body.identifier);
      const password = validatePassword(body.password);
      const userId = randomUUID();
      const timestamp = new Date().toISOString();
      try {
        transact(database, () => {
          if (database.prepare("SELECT 1 FROM users LIMIT 1").get()) {
            throw new ApiError(409, "This workspace already has an owner. Sign in instead.");
          }
          database.prepare(`
            INSERT INTO users (id, name, email, phone, password_hash, role, created_at)
            VALUES (?, ?, ?, ?, ?, 'owner', ?)
          `).run(userId, name, contact.email, contact.phone, passwordHash(password), timestamp);
        });
      } catch (error) {
        if (error instanceof ApiError) {
          throw error;
        }
        if (isConstraintError(error)) {
          throw new ApiError(409, "This owner account could not be created. Check the email or phone number and try again.");
        }
        throw error;
      }
      const user = createSession(response, userId);
      respond(response, 201, { user, setupComplete: true });
      return;
    }

    if (pathname === "/api/auth/login" && method === "POST") {
      const body = await readJson(request);
      verifyBodyShape(body, new Set(["identifier", "password", "rememberMe"]));
      const identifier = typeof body.identifier === "string" ? body.identifier.trim().slice(0, 254) : "";
      const loginContact = parseLoginIdentifier(identifier);
      const key = rateKey("password-login", request, loginContact?.email ?? loginContact?.phone ?? "invalid");
      enforceRateLimit(key, 5, 15 * 60 * 1000);
      const user = loginContact
        ? database.prepare("SELECT * FROM users WHERE (email = ? COLLATE NOCASE AND ? IS NOT NULL) OR (phone = ? AND ? IS NOT NULL)")
          .get(loginContact.email, loginContact.email, loginContact.phone, loginContact.phone)
        : undefined;
      const password = typeof body.password === "string" ? body.password : "";
      const matches = passwordMatches(password, user?.password_hash ?? dummyPasswordHash);
      if (!user || !matches) {
        throw new ApiError(401, "The email, phone number or password is incorrect.");
      }
      resetRateLimit(key);
      const publicProfile = createSession(response, user.id, body.rememberMe === true);
      respond(response, 200, { user: publicProfile });
      return;
    }

    if (pathname === "/api/auth/logout" && method === "POST") {
      const token = cookieToken(request);
      if (token) {
        database.prepare("DELETE FROM sessions WHERE token_hash = ?").run(hash(token));
      }
      response.setHeader("Set-Cookie", clearCookie(secureCookie));
      respond(response, 200, { ok: true });
      return;
    }

    if (pathname === "/api/auth/change-password" && method === "POST") {
      const session = requireSession(request, pathname);
      const body = await readJson(request);
      verifyBodyShape(body, new Set(["currentPassword", "newPassword"]));
      const account = database.prepare("SELECT id, password_hash FROM users WHERE id = ?").get(session.id);
      const currentPassword = typeof body.currentPassword === "string" ? body.currentPassword : "";
      if (!passwordMatches(currentPassword, account.password_hash)) {
        throw new ApiError(401, "The current password is incorrect.");
      }
      const nextPassword = validatePassword(body.newPassword);
      if (passwordMatches(nextPassword, account.password_hash)) {
        throw new ApiError(400, "Choose a password you have not used for this account.");
      }
      const now = Date.now();
      database.prepare("UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?")
        .run(passwordHash(nextPassword), session.id);
      database.prepare("UPDATE sessions SET reauthenticated_at = ?, expires_at = ? WHERE token_hash = ?")
        .run(now, now + SESSION_HOURS * 60 * 60 * 1000, session.token_hash);
      respond(response, 200, { user: publicUser(rowUser(database, session.id)) });
      return;
    }

    if (pathname === "/api/auth/reauth" && method === "POST") {
      const session = requireSession(request, pathname);
      const body = await readJson(request);
      verifyBodyShape(body, new Set(["password"]));
      const account = database.prepare("SELECT password_hash FROM users WHERE id = ?").get(session.id);
      const password = typeof body.password === "string" ? body.password : "";
      if (!passwordMatches(password, account.password_hash)) {
        throw new ApiError(401, "The password is incorrect.");
      }
      database.prepare("UPDATE sessions SET reauthenticated_at = ? WHERE token_hash = ?")
        .run(Date.now(), session.token_hash);
      respond(response, 200, { ok: true });
      return;
    }

    if (pathname === "/api/auth/passkeys/authentication/options" && method === "POST") {
      const body = await readJson(request);
      verifyBodyShape(body, new Set());
      const key = rateKey("passkey-options", request);
      enforceRateLimit(key, 12, 60 * 1000);
      cleanChallenges(authenticationChallenges, Date.now());
      const optionsJSON = await generateAuthenticationOptions({
        rpID: relyingPartyId,
        userVerification: "required",
        timeout: 60_000,
      });
      if (authenticationChallenges.size >= 10_000) {
        throw new ApiError(503, "The passkey service is temporarily busy. Please try again.");
      }
      authenticationChallenges.set(optionsJSON.challenge, { expiresAt: Date.now() + CHALLENGE_TTL });
      respond(response, 200, optionsJSON);
      return;
    }

    if (pathname === "/api/auth/passkeys/authentication/verify" && method === "POST") {
      const body = await readJson(request);
      const credentialId = requiredText(body.id, "Passkey ID", 2048);
      const rawClientData = body.response?.clientDataJSON;
      if (typeof rawClientData !== "string" || rawClientData.length > 32_768) {
        throw new ApiError(400, "The passkey response is incomplete.");
      }
      let challenge;
      try {
        challenge = JSON.parse(Buffer.from(rawClientData, "base64url").toString("utf8")).challenge;
      } catch {
        throw new ApiError(400, "The passkey response is invalid.");
      }
      const pending = authenticationChallenges.get(challenge);
      authenticationChallenges.delete(challenge);
      if (!pending || pending.expiresAt <= Date.now()) {
        throw new ApiError(401, "This passkey request expired. Please try again.");
      }
      const key = rateKey("passkey-login", request);
      enforceRateLimit(key, 8, 15 * 60 * 1000);
      const passkey = database.prepare("SELECT * FROM passkeys WHERE credential_id = ?").get(credentialId);
      if (!passkey) {
        throw new ApiError(401, "This passkey could not be verified.");
      }
      let verification;
      try {
        verification = await verifyAuthenticationResponse({
          response: body,
          expectedChallenge: challenge,
          expectedOrigin: configuredOrigin,
          expectedRPID: relyingPartyId,
          credential: {
            id: passkey.credential_id,
            publicKey: new Uint8Array(passkey.public_key),
            counter: passkey.counter,
            transports: JSON.parse(passkey.transports),
          },
          requireUserVerification: true,
        });
      } catch {
        throw new ApiError(401, "This passkey could not be verified.");
      }
      if (!verification.verified) {
        throw new ApiError(401, "This passkey could not be verified.");
      }
      database.prepare("UPDATE passkeys SET counter = ? WHERE credential_id = ?")
        .run(verification.authenticationInfo.newCounter, passkey.credential_id);
      const user = createSession(response, passkey.user_id);
      respond(response, 200, { user });
      return;
    }

    const session = requireSession(request, pathname);

    if (pathname === "/api/events" && method === "GET") {
      const activeConnections = [...eventClients].filter((client) => client.tokenHash === session.token_hash).length;
      if (activeConnections >= 8 || eventClients.size >= 1000) {
        throw new ApiError(503, "The live updates service is temporarily busy. Please try again.");
      }
      response.writeHead(200, {
        "Content-Type": "text/event-stream; charset=utf-8",
        "Cache-Control": "no-cache, no-transform",
        Connection: "keep-alive",
        "X-Accel-Buffering": "no",
      });
      const client = { response, tokenHash: session.token_hash, heartbeat: null };
      eventClients.add(client);
      response.on("close", () => closeEventClient(client));
      client.heartbeat = setInterval(() => {
        const active = database.prepare("SELECT 1 FROM sessions WHERE token_hash = ? AND expires_at > ?")
          .get(client.tokenHash, Date.now());
        if (!active) {
          response.write("event: session-expired\ndata: {}\n\n");
          closeEventClient(client);
          response.end();
          return;
        }
        response.write(": heartbeat\n\n");
      }, 20_000);
      client.heartbeat.unref();
      response.write("event: ready\ndata: {}\n\n");
      return;
    }

    if (pathname === "/api/me" && method === "GET") {
      const profile = publicUser(rowUser(database, session.id));
      const passkeys = database.prepare(`
        SELECT credential_id AS id, name, created_at AS createdAt, transports
        FROM passkeys WHERE user_id = ? ORDER BY created_at DESC
      `).all(session.id).map((passkey) => ({
        id: passkey.id,
        name: passkey.name,
        createdAt: passkey.createdAt,
        transports: JSON.parse(passkey.transports),
      }));
      respond(response, 200, { user: profile, passkeys });
      return;
    }

    if (pathname === "/api/auth/passkeys/registration/options" && method === "POST") {
      requireRecentAuthentication(session);
      const body = await readJson(request);
      verifyBodyShape(body, new Set());
      cleanChallenges(registrationChallenges, Date.now());
      const optionsJSON = await generateRegistrationOptions({
        rpName: "ANUCHO",
        rpID: relyingPartyId,
        userID: Buffer.from(session.id, "utf8"),
        userName: session.email ?? session.phone,
        userDisplayName: session.name,
        attestationType: "none",
        supportedAlgorithmIDs: [-7, -257],
        authenticatorSelection: {
          authenticatorAttachment: "platform",
          residentKey: "required",
          userVerification: "required",
        },
        excludeCredentials: database.prepare(`
          SELECT credential_id AS id, transports FROM passkeys WHERE user_id = ?
        `).all(session.id).map((credential) => ({
          id: credential.id,
          transports: JSON.parse(credential.transports),
        })),
        timeout: 60_000,
      });
      if (registrationChallenges.size >= 10_000) {
        throw new ApiError(503, "The passkey service is temporarily busy. Please try again.");
      }
      registrationChallenges.set(session.token_hash, {
        challenge: optionsJSON.challenge,
        userId: session.id,
        expiresAt: Date.now() + CHALLENGE_TTL,
      });
      respond(response, 200, optionsJSON);
      return;
    }

    if (pathname === "/api/auth/passkeys/registration/verify" && method === "POST") {
      requireRecentAuthentication(session);
      const body = await readJson(request);
      verifyBodyShape(body, new Set(["credential", "name"]));
      const pending = registrationChallenges.get(session.token_hash);
      registrationChallenges.delete(session.token_hash);
      if (!pending || pending.userId !== session.id || pending.expiresAt <= Date.now()) {
        throw new ApiError(401, "This passkey registration expired. Please start again.");
      }
      let verification;
      try {
        verification = await verifyRegistrationResponse({
          response: body.credential,
          expectedChallenge: pending.challenge,
          expectedOrigin: configuredOrigin,
          expectedRPID: relyingPartyId,
          requireUserVerification: true,
        });
      } catch {
        throw new ApiError(400, "The authenticator response could not be verified.");
      }
      if (!verification.verified || !verification.registrationInfo) {
        throw new ApiError(400, "The authenticator response could not be verified.");
      }
      const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
      const name = optionalText(body.name, "Device name", 80) || "This device";
      try {
        database.prepare(`
          INSERT INTO passkeys (credential_id, user_id, public_key, counter, transports, device_type, backed_up, name, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          credential.id,
          session.id,
          Buffer.from(credential.publicKey),
          credential.counter,
          JSON.stringify(credential.transports ?? []),
          credentialDeviceType,
          Number(credentialBackedUp),
          name,
          new Date().toISOString(),
        );
      } catch {
        throw new ApiError(409, "This passkey is already registered to an account.");
      }
      respond(response, 201, { ok: true, passkey: { id: credential.id, name } });
      return;
    }

    const passkeyMatch = pathname.match(/^\/api\/auth\/passkeys\/([^/]+)$/);
    if (passkeyMatch && method === "DELETE") {
      requireRecentAuthentication(session);
      const credentialId = decodeURIComponent(passkeyMatch[1]);
      const result = database.prepare("DELETE FROM passkeys WHERE credential_id = ? AND user_id = ?")
        .run(credentialId, session.id);
      if (result.changes === 0) {
        throw new ApiError(404, "Passkey not found.");
      }
      respond(response, 200, { ok: true });
      return;
    }

    if (pathname === "/api/overview" && method === "GET") {
      const counts = database.prepare(`
        SELECT COUNT(*) AS total,
          SUM(CASE WHEN status IN ('pending', 'filed', 'in_review') THEN 1 ELSE 0 END) AS applications,
          SUM(CASE WHEN renewal_date != '' AND renewal_date >= date('now')
            AND renewal_date <= date('now', '+90 days') THEN 1 ELSE 0 END) AS renewals_due,
          SUM(estimated_value) AS value
        FROM patents
      `).get();
      const status = database.prepare("SELECT status, COUNT(*) AS count FROM patents GROUP BY status ORDER BY status").all();
      const recentPatents = database.prepare("SELECT * FROM patents ORDER BY updated_at DESC LIMIT 5").all().map(parsePatent);
      const months = [];
      const today = new Date();
      const monthStart = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth() - 11, 1));
      const growthRows = database.prepare(`
        SELECT substr(CASE WHEN filing_date = '' THEN created_at ELSE filing_date END, 1, 7) AS month,
          COUNT(*) AS count FROM patents
        WHERE substr(CASE WHEN filing_date = '' THEN created_at ELSE filing_date END, 1, 7) >= ?
        GROUP BY month
      `).all(monthStart.toISOString().slice(0, 7));
      const growth = new Map(growthRows.map((row) => [row.month, Number(row.count)]));
      for (let offset = 0; offset < 12; offset += 1) {
        const month = new Date(Date.UTC(monthStart.getUTCFullYear(), monthStart.getUTCMonth() + offset, 1));
        months.push({
          month: month.toISOString().slice(0, 7),
          count: growth.get(month.toISOString().slice(0, 7)) ?? 0,
        });
      }
      respond(response, 200, {
        totalPatents: Number(counts.total),
        activeApplications: Number(counts.applications ?? 0),
        renewalsDue: Number(counts.renewals_due ?? 0),
        estimatedPortfolioValue: Number(counts.value ?? 0),
        byStatus: status.map((row) => ({ status: row.status, count: Number(row.count) })),
        recentPatents,
        growth: months,
      });
      return;
    }

    if (pathname === "/api/sales.csv" && method === "GET") {
      checkMethod(request, ["GET"]);
      const records = database.prepare("SELECT * FROM sales ORDER BY created_at DESC").all();
      let output = csvRow(["Receipt", "Date", "Customer", "Payment method", "Status", "Refund reason", "Items", "Subtotal", "Tax", "Total", "Cash received", "Change"]);
      for (const row of records) {
        const sale = parseSale(row);
        output += csvRow([
          sale.receiptNumber,
          sale.createdAt,
          sale.customerName,
          sale.paymentMethod,
          sale.status,
          sale.refundReason,
          sale.items.map((item) => `${item.quantity} x ${item.name}`).join("; "),
          (sale.subtotalCents / 100).toFixed(2),
          (sale.taxCents / 100).toFixed(2),
          (sale.totalCents / 100).toFixed(2),
          (sale.amountReceivedCents / 100).toFixed(2),
          (sale.changeCents / 100).toFixed(2),
        ]);
      }
      response.writeHead(200, {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": 'attachment; filename="anucho-sales.csv"',
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
      });
      response.end(output);
      return;
    }

    if (pathname === "/api/reports.csv" && method === "GET") {
      checkMethod(request, ["GET"]);
      const records = database.prepare("SELECT * FROM patents ORDER BY updated_at DESC").all();
      let output = csvRow(["Patent", "Patent number", "Owner", "Category", "Status", "Filing date", "Renewal date", "Estimated value", "Description"]);
      for (const row of records) {
        output += csvRow([
          row.title, row.patent_number, row.owner, row.category, row.status,
          row.filing_date, row.renewal_date, row.estimated_value, row.description,
        ]);
      }
      response.writeHead(200, {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": 'attachment; filename="anucho-patents.csv"',
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
      });
      response.end(output);
      return;
    }

    if (pathname === "/api/reports" && method === "GET") {
      const storeDate = currentStoreDate();
      const overviewResponse = {
        totalPatents: Number(database.prepare("SELECT COUNT(*) AS count FROM patents").get().count),
        byStatus: database.prepare("SELECT status, COUNT(*) AS count FROM patents GROUP BY status ORDER BY status").all()
          .map((row) => ({ status: row.status, count: Number(row.count) })),
        renewalsDue: Number(database.prepare(`
          SELECT COUNT(*) AS count FROM patents
          WHERE renewal_date != '' AND renewal_date >= date('now') AND renewal_date <= date('now', '+90 days')
        `).get().count),
        estimatedPortfolioValue: Number(database.prepare("SELECT COALESCE(SUM(estimated_value), 0) AS value FROM patents").get().value),
        suppliers: Number(database.prepare("SELECT COUNT(*) AS count FROM suppliers").get().count),
        products: Number(database.prepare("SELECT COUNT(*) AS count FROM products").get().count),
        todaySalesCount: Number(database.prepare(`
          SELECT COUNT(*) AS count FROM sales WHERE status = 'completed' AND substr(created_at, 1, 10) = ?
        `).get(storeDate).count),
        todayRevenueCents: Number(database.prepare(`
          SELECT COALESCE(SUM(total_cents), 0) AS total FROM sales WHERE status = 'completed' AND substr(created_at, 1, 10) = ?
        `).get(storeDate).total),
        lowStockCount: Number(database.prepare("SELECT COUNT(*) AS count FROM products WHERE stock_quantity <= 5").get().count),
      };
      respond(response, 200, overviewResponse);
      return;
    }

    if (pathname === "/api/patents" || pathname.startsWith("/api/patents/")) {
      const id = pathname === "/api/patents" ? null : decodeURIComponent(pathname.slice("/api/patents/".length));
      if (!id) {
        checkMethod(request, ["GET", "POST"]);
        if (method === "GET") {
          respond(response, 200, { patents: listPatents(url.searchParams.get("q") ?? "") });
          return;
        }
        const body = await readJson(request);
        verifyBodyShape(body, new Set(["title", "patentNumber", "owner", "category", "status", "filingDate", "renewalDate", "estimatedValue", "description"]));
        requireWriter(session);
        const saved = writePatent(body, session.id);
        respond(response, 201, { patent: saved });
        return;
      }
      checkMethod(request, ["GET", "PUT", "PATCH", "DELETE"]);
      const current = database.prepare("SELECT * FROM patents WHERE id = ?").get(id);
      if (!current) {
        throw new ApiError(404, "Patent not found.");
      }
      if (method === "GET") {
        respond(response, 200, { patent: parsePatent(current) });
      } else if (method === "DELETE") {
        requireWriter(session);
        database.prepare("DELETE FROM patents WHERE id = ?").run(id);
        respond(response, 200, { ok: true });
      } else {
        const body = await readJson(request);
        verifyBodyShape(body, new Set(["title", "patentNumber", "owner", "category", "status", "filingDate", "renewalDate", "estimatedValue", "description"]));
        requireWriter(session);
        respond(response, 200, { patent: writePatent(body, session.id, parsePatent(current)) });
      }
      return;
    }

    if (pathname === "/api/products" || pathname.startsWith("/api/products/")) {
      const id = pathname === "/api/products" ? null : decodeURIComponent(pathname.slice("/api/products/".length));
      if (!id) {
        checkMethod(request, ["GET", "POST"]);
        if (method === "GET") {
          respond(response, 200, { products: listProducts(url.searchParams.get("q") ?? "") });
          return;
        }
        const body = await readJson(request);
        verifyBodyShape(body, new Set(["name", "category", "description", "sku", "price", "stockQuantity", "patentIds"]));
        requireWriter(session);
        respond(response, 201, { product: writeProduct(body) });
        return;
      }
      checkMethod(request, ["GET", "PUT", "PATCH", "DELETE"]);
      const current = parseProduct(database, database.prepare("SELECT * FROM products WHERE id = ?").get(id));
      if (!current) {
        throw new ApiError(404, "Product not found.");
      }
      if (method === "GET") {
        respond(response, 200, { product: current });
      } else if (method === "DELETE") {
        requireWriter(session);
        database.prepare("DELETE FROM products WHERE id = ?").run(id);
        respond(response, 200, { ok: true });
      } else {
        const body = await readJson(request);
        verifyBodyShape(body, new Set(["name", "category", "description", "sku", "price", "stockQuantity", "patentIds"]));
        requireWriter(session);
        respond(response, 200, { product: writeProduct(body, current) });
      }
      return;
    }

    if (pathname === "/api/sales" && method === "GET") {
      const sales = database.prepare("SELECT * FROM sales ORDER BY created_at DESC LIMIT 100").all().map(parseSale);
      const totals = database.prepare(`
        SELECT COUNT(*) AS count, COALESCE(SUM(total_cents), 0) AS revenue
        FROM sales WHERE status = 'completed' AND substr(created_at, 1, 10) = ?
      `).get(currentStoreDate());
      const lowStock = database.prepare("SELECT COUNT(*) AS count FROM products WHERE stock_quantity <= 5").get();
      respond(response, 200, {
        sales,
        summary: {
          todayCount: Number(totals.count),
          todayRevenueCents: Number(totals.revenue),
          lowStockCount: Number(lowStock.count),
        },
      });
      return;
    }

    if (pathname === "/api/sales" && method === "POST") {
      requireWriter(session);
      const body = await readJson(request);
      verifyBodyShape(body, new Set(["items", "paymentMethod", "amountReceived", "customerName"]));
      if (!Array.isArray(body.items) || body.items.length < 1 || body.items.length > 100) {
        throw new ApiError(400, "A sale must contain between 1 and 100 products.");
      }
      const paymentMethod = requiredText(body.paymentMethod, "Payment method", 16).toLowerCase();
      if (!["cash", "card", "other"].includes(paymentMethod)) {
        throw new ApiError(400, "Choose cash, card, or other as the payment method.");
      }
      const customerName = optionalText(body.customerName, "Customer name", 120);
      const lineItems = [];
      const productIds = new Set();
      for (const item of body.items) {
        if (!item || typeof item !== "object" || Array.isArray(item)) {
          throw new ApiError(400, "Each sale item must include a product and quantity.");
        }
        verifyBodyShape(item, new Set(["productId", "quantity"]));
        const productId = requiredText(item.productId, "Product ID", 64);
        const quantity = stockCount(item.quantity, "Item quantity");
        if (!quantity) {
          throw new ApiError(400, "Item quantity must be at least one.");
        }
        if (productIds.has(productId)) {
          throw new ApiError(400, "Each product may only appear once in a sale.");
        }
        productIds.add(productId);
        lineItems.push({ productId, quantity });
      }

      const saleId = randomUUID();
      const receiptNumber = `AN-${new Date().toISOString().slice(0, 10).replace(/-/g, "")}-${randomBytes(3).toString("hex").toUpperCase()}`;
      const createdAt = new Date().toISOString();
      let sale;
      transact(database, () => {
        const items = lineItems.map(({ productId, quantity }) => {
          const product = database.prepare("SELECT * FROM products WHERE id = ?").get(productId);
          if (!product) {
            throw new ApiError(404, "A product in this sale is no longer available.");
          }
          if (Number(product.stock_quantity) < quantity) {
            throw new ApiError(409, `${product.name} does not have enough stock for this sale.`);
          }
          const unitPriceCents = Number(product.price_cents);
          return {
            productId,
            name: product.name,
            sku: product.sku,
            quantity,
            unitPriceCents,
            lineTotalCents: unitPriceCents * quantity,
          };
        });
        const subtotalCents = items.reduce((total, item) => total + item.lineTotalCents, 0);
        const taxSetting = database.prepare("SELECT setting_value FROM settings WHERE setting_key = 'taxRate'").get();
        const taxRate = taxSetting ? Number(JSON.parse(taxSetting.setting_value)) : 0;
        const taxCents = Math.round(subtotalCents * taxRate / 100);
        const totalCents = subtotalCents + taxCents;
        if (!Number.isSafeInteger(totalCents)) {
          throw new ApiError(400, "The sale total is too large to process.");
        }
        const amountReceivedCents = paymentMethod === "cash"
          ? priceInCents(body.amountReceived, "Amount received")
          : totalCents;
        if (amountReceivedCents < totalCents) {
          throw new ApiError(400, "The amount received must cover the sale total.");
        }
        const updateStock = database.prepare(`
          UPDATE products SET stock_quantity = stock_quantity - ?, updated_at = ?
          WHERE id = ? AND stock_quantity >= ?
        `);
        for (const item of items) {
          const updated = updateStock.run(item.quantity, createdAt, item.productId, item.quantity);
          if (updated.changes !== 1) {
            throw new ApiError(409, "Stock changed while this sale was being completed. Review the cart and try again.");
          }
        }
        database.prepare(`
          INSERT INTO sales
            (id, receipt_number, cashier_id, customer_name, items, subtotal_cents, tax_cents,
             total_cents, amount_received_cents, change_cents, payment_method, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          saleId, receiptNumber, session.id, customerName, JSON.stringify(items), subtotalCents, taxCents,
          totalCents, amountReceivedCents, amountReceivedCents - totalCents, paymentMethod, createdAt,
        );
        sale = parseSale(database.prepare("SELECT * FROM sales WHERE id = ?").get(saleId));
      });
      respond(response, 201, { sale });
      return;
    }

    const saleRefundMatch = pathname.match(/^\/api\/sales\/([^/]+)\/refund$/);
    if (saleRefundMatch && method === "POST") {
      requireWriter(session);
      const body = await readJson(request);
      verifyBodyShape(body, new Set(["reason"]));
      const reason = requiredText(body.reason, "Refund reason", 240);
      const saleId = decodeURIComponent(saleRefundMatch[1]);
      let sale;
      transact(database, () => {
        const row = database.prepare("SELECT * FROM sales WHERE id = ?").get(saleId);
        if (!row) {
          throw new ApiError(404, "Sale not found.");
        }
        if (row.status !== "completed") {
          throw new ApiError(409, "This sale has already been refunded.");
        }
        const items = JSON.parse(row.items);
        for (const item of items) {
          const restored = database.prepare(`
            UPDATE products SET stock_quantity = stock_quantity + ?, updated_at = ?
            WHERE id = ?
          `).run(item.quantity, new Date().toISOString(), item.productId);
          if (restored.changes !== 1) {
            throw new ApiError(409, `Cannot restore stock for ${item.name}; its product record no longer exists.`);
          }
        }
        database.prepare(`
          UPDATE sales SET status = 'refunded', refunded_at = ?, refunded_by = ?, refund_reason = ?
          WHERE id = ? AND status = 'completed'
        `).run(new Date().toISOString(), session.id, reason, saleId);
        sale = parseSale(database.prepare("SELECT * FROM sales WHERE id = ?").get(saleId));
      });
      respond(response, 200, { sale });
      return;
    }

    if (pathname === "/api/suppliers" || pathname.startsWith("/api/suppliers/")) {
      const id = pathname === "/api/suppliers" ? null : decodeURIComponent(pathname.slice("/api/suppliers/".length));
      if (!id) {
        checkMethod(request, ["GET", "POST"]);
        if (method === "GET") {
          respond(response, 200, { suppliers: listSuppliers(url.searchParams.get("q") ?? "") });
          return;
        }
        const body = await readJson(request);
        verifyBodyShape(body, new Set(["name", "service", "email", "phone", "status", "notes"]));
        requireWriter(session);
        respond(response, 201, { supplier: writeSupplier(body) });
        return;
      }
      checkMethod(request, ["GET", "PUT", "PATCH", "DELETE"]);
      const current = parseSupplier(database.prepare("SELECT * FROM suppliers WHERE id = ?").get(id));
      if (!current) {
        throw new ApiError(404, "Supplier not found.");
      }
      if (method === "GET") {
        respond(response, 200, { supplier: current });
      } else if (method === "DELETE") {
        requireWriter(session);
        database.prepare("DELETE FROM suppliers WHERE id = ?").run(id);
        respond(response, 200, { ok: true });
      } else {
        const body = await readJson(request);
        verifyBodyShape(body, new Set(["name", "service", "email", "phone", "status", "notes"]));
        requireWriter(session);
        respond(response, 200, { supplier: writeSupplier(body, current) });
      }
      return;
    }

    if (pathname === "/api/collections" || pathname.startsWith("/api/collections/")) {
      const id = pathname === "/api/collections" ? null : decodeURIComponent(pathname.slice("/api/collections/".length));
      if (!id) {
        checkMethod(request, ["GET", "POST"]);
        if (method === "GET") {
          respond(response, 200, { collections: listCollections() });
          return;
        }
        const body = await readJson(request);
        verifyBodyShape(body, new Set(["name", "description", "isPublic", "patentIds"]));
        requireWriter(session);
        respond(response, 201, { collection: writeCollection(body) });
        return;
      }
      checkMethod(request, ["GET", "PUT", "PATCH", "DELETE"]);
      const current = parseCollection(database.prepare("SELECT * FROM collections WHERE id = ?").get(id));
      if (!current) {
        throw new ApiError(404, "Collection not found.");
      }
      if (method === "GET") {
        respond(response, 200, { collection: current });
      } else if (method === "DELETE") {
        requireWriter(session);
        database.prepare("DELETE FROM collections WHERE id = ?").run(id);
        respond(response, 200, { ok: true });
      } else {
        const body = await readJson(request);
        verifyBodyShape(body, new Set(["name", "description", "isPublic", "patentIds"]));
        requireWriter(session);
        respond(response, 200, { collection: writeCollection(body, current) });
      }
      return;
    }

    if (pathname === "/api/settings" && method === "GET") {
      const values = database.prepare("SELECT setting_key, setting_value FROM settings ORDER BY setting_key").all();
      respond(response, 200, { settings: Object.fromEntries(values.map((item) => [item.setting_key, JSON.parse(item.setting_value)])) });
      return;
    }
    if (pathname === "/api/settings" && method === "PATCH") {
      requireOwner(session);
      const body = await readJson(request);
      verifyBodyShape(body, new Set(["workspaceName", "currency", "timezone", "taxRate"]));
      const updates = {};
      if ("workspaceName" in body) {
        updates.workspaceName = requiredText(body.workspaceName, "Workspace name", 120);
      }
      if ("currency" in body) {
        const currency = requiredText(body.currency, "Currency", 3).toUpperCase();
        if (!/^[A-Z]{3}$/.test(currency)) {
          throw new ApiError(400, "Enter a valid three-letter currency code.");
        }
        updates.currency = currency;
      }
      if ("timezone" in body) {
        const timezone = requiredText(body.timezone, "Time zone", 80);
        try {
          new Intl.DateTimeFormat("en", { timeZone: timezone });
        } catch {
          throw new ApiError(400, "Enter a valid time zone.");
        }
        updates.timezone = timezone;
      }
      if ("taxRate" in body) {
        const taxRate = Number(body.taxRate);
        if (!Number.isFinite(taxRate) || taxRate < 0 || taxRate > 100) {
          throw new ApiError(400, "Tax rate must be between 0 and 100 percent.");
        }
        updates.taxRate = Math.round(taxRate * 100) / 100;
      }
      transact(database, () => {
        const upsert = database.prepare(`
          INSERT INTO settings (setting_key, setting_value) VALUES (?, ?)
          ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value
        `);
        for (const [key, value] of Object.entries(updates)) {
          upsert.run(key, JSON.stringify(value));
        }
      });
      const values = database.prepare("SELECT setting_key, setting_value FROM settings ORDER BY setting_key").all();
      respond(response, 200, { settings: Object.fromEntries(values.map((item) => [item.setting_key, JSON.parse(item.setting_value)])) });
      return;
    }

    if (pathname === "/api/team" && method === "GET") {
      requireOwner(session);
      const members = database.prepare(`
        SELECT id, name, email, phone, role, must_change_password, created_at,
          (SELECT COUNT(*) FROM passkeys WHERE passkeys.user_id = users.id) AS passkey_count
        FROM users ORDER BY created_at
      `).all().map(publicUser);
      respond(response, 200, { members });
      return;
    }
    if (pathname === "/api/team" && method === "POST") {
      requireOwner(session);
      const body = await readJson(request);
      verifyBodyShape(body, new Set(["name", "identifier", "role"]));
      const name = requiredText(body.name, "Name", 120);
      const contact = contactFromIdentifier(body.identifier);
      const role = requiredText(body.role ?? "editor", "Role", 32);
      if (!["editor", "reviewer"].includes(role)) {
        throw new ApiError(400, "Choose the editor or reviewer role.");
      }
      const temporaryPassword = randomBytes(24).toString("base64url");
      const memberId = randomUUID();
      try {
        database.prepare(`
          INSERT INTO users (id, name, email, phone, password_hash, role, must_change_password, created_at)
          VALUES (?, ?, ?, ?, ?, ?, 1, ?)
        `).run(memberId, name, contact.email, contact.phone, passwordHash(temporaryPassword), role, new Date().toISOString());
      } catch {
        throw new ApiError(409, "An account with that email address or phone number already exists.");
      }
      respond(response, 201, { member: publicUser(rowUser(database, memberId)), temporaryPassword });
      return;
    }

    const resetMemberMatch = pathname.match(/^\/api\/team\/([^/]+)\/reset-password$/);
    if (resetMemberMatch) {
      requireOwner(session);
      checkMethod(request, ["POST"]);
      const memberId = decodeURIComponent(resetMemberMatch[1]);
      if (memberId === session.id) {
        throw new ApiError(409, "Use Settings to change your own password.");
      }
      const member = database.prepare("SELECT id FROM users WHERE id = ?").get(memberId);
      if (!member) {
        throw new ApiError(404, "Team member not found.");
      }
      const temporaryPassword = randomBytes(24).toString("base64url");
      database.prepare("UPDATE users SET password_hash = ?, must_change_password = 1 WHERE id = ?")
        .run(passwordHash(temporaryPassword), memberId);
      database.prepare("DELETE FROM sessions WHERE user_id = ?").run(memberId);
      respond(response, 200, { member: publicUser(rowUser(database, memberId)), temporaryPassword });
      return;
    }

    const memberMatch = pathname.match(/^\/api\/team\/([^/]+)$/);
    if (memberMatch) {
      requireOwner(session);
      const memberId = decodeURIComponent(memberMatch[1]);
      const member = database.prepare("SELECT * FROM users WHERE id = ?").get(memberId);
      if (!member) {
        throw new ApiError(404, "Team member not found.");
      }
      if (method === "PATCH") {
        const body = await readJson(request);
        verifyBodyShape(body, new Set(["role", "name"]));
        const name = body.name === undefined ? member.name : requiredText(body.name, "Name", 120);
        const role = body.role === undefined ? member.role : requiredText(body.role, "Role", 32);
        if (!USER_ROLES.has(role) || (role === "owner" && session.id !== memberId)) {
          throw new ApiError(400, "Only the current owner can retain the owner role.");
        }
        if (member.role === "owner" && role !== "owner") {
          const otherOwners = database.prepare("SELECT COUNT(*) AS count FROM users WHERE role = 'owner' AND id != ?").get(memberId).count;
          if (otherOwners === 0) {
            throw new ApiError(409, "Transfer the owner role before changing this account.");
          }
        }
        database.prepare("UPDATE users SET name = ?, role = ? WHERE id = ?").run(name, role, memberId);
        respond(response, 200, { member: publicUser(rowUser(database, memberId)) });
        return;
      }
      if (method === "DELETE") {
        if (memberId === session.id || member.role === "owner") {
          throw new ApiError(409, "The workspace owner cannot be removed.");
        }
        database.prepare("DELETE FROM users WHERE id = ?").run(memberId);
        respond(response, 200, { ok: true });
        return;
      }
      checkMethod(request, ["PATCH", "DELETE"]);
      return;
    }

    throw new ApiError(404, "Page or API route not found.");
  }

  const httpServer = createHttpServer((request, response) => {
    response.setHeader("X-Content-Type-Options", "nosniff");
    response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    const requestUrl = new URL(request.url, configuredOrigin);
    Promise.resolve(handle(request, response))
      .then(() => {
        if (response.statusCode >= 200 && response.statusCode < 300) {
          const resources = changedResources(request.method, requestUrl.pathname);
          const token = cookieToken(request);
          if (resources.length) {
            publishWorkspaceChange(resources, token ? hash(token) : null);
          }
        }
      })
      .catch((error) => {
        if (response.headersSent) {
          response.destroy();
          return;
        }
        if (error instanceof ApiError) {
          respond(response, error.status, { error: error.message }, error.headers);
          return;
        }
        if (isConstraintError(error)) {
          respond(response, 409, { error: "This change conflicts with an existing workspace record." });
          return;
        }
        console.error(`[ANUCHO] ${request.method} ${request.url}:`, error);
        respond(response, 500, { error: "An unexpected server error occurred." });
      });
  });

  return {
    server: httpServer,
    database,
    origin: configuredOrigin,
    port,
    host,
    close() {
      for (const client of eventClients) {
        closeEventClient(client);
        client.response.end();
      }
      database.close();
    },
  };
}

function runServer() {
  const service = createServer();
  service.server.listen(service.port, service.host, () => {
    console.log(`ANUCHO is running at ${service.origin}`);
  });
  const close = () => {
    service.server.close(() => {
      service.close();
      process.exitCode = 0;
    });
  };
  process.once("SIGINT", close);
  process.once("SIGTERM", close);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    runServer();
  } catch (error) {
    console.error("[ANUCHO] Failed to start:", error);
    process.exitCode = 1;
  }
}
