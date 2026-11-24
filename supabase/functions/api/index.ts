import { createClient } from "npm:@supabase/supabase-js@2";

type Role = "owner" | "editor" | "reviewer";
type Session = { id: string; role: Role; name: string; mustChangePassword: boolean };

class ApiError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

const supabaseUrl = Deno.env.get("SUPABASE_URL");
const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
if (!supabaseUrl || !anonKey || !serviceRoleKey) {
  throw new Error("SUPABASE_URL, SUPABASE_ANON_KEY, and SUPABASE_SERVICE_ROLE_KEY are required.");
}

const admin = createClient(supabaseUrl, serviceRoleKey, {
  auth: { autoRefreshToken: false, persistSession: false },
});
const allowedOrigins = new Set((Deno.env.get("ANUCHO_ALLOWED_ORIGINS") ?? "")
  .split(",").map((origin) => origin.trim()).filter(Boolean));
const roles = new Set<Role>(["owner", "editor", "reviewer"]);
const writerRoles = new Set<Role>(["owner", "editor"]);

function json(body: unknown, status = 200, headers: HeadersInit = {}) {
  const responseHeaders = new Headers(headers);
  responseHeaders.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(body), {
    status,
    headers: responseHeaders,
  });
}

function ensureAllowedOrigin(request: Request) {
  const origin = request.headers.get("Origin");
  if (origin && allowedOrigins.size && !allowedOrigins.has(origin)) {
    throw new ApiError(403, "The request origin could not be verified.");
  }
}

async function bodyJson(request: Request) {
  try {
    const body = await request.json();
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      throw new ApiError(400, "Send a JSON object.");
    }
    return body as Record<string, unknown>;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(400, "Send a valid JSON object.");
  }
}

function allowedFields(body: Record<string, unknown>, fields: string[]) {
  const extra = Object.keys(body).find((key) => !fields.includes(key));
  if (extra) throw new ApiError(400, `Unknown field: ${extra}.`);
}

function text(value: unknown, label: string, maximum: number, required = false) {
  if (value == null || value === "") {
    if (required) throw new ApiError(400, `${label} is required.`);
    return "";
  }
  if (typeof value !== "string") throw new ApiError(400, `${label} must be text.`);
  const result = value.trim();
  if (!result && required) throw new ApiError(400, `${label} is required.`);
  if (result.length > maximum) throw new ApiError(400, `${label} must be ${maximum} characters or fewer.`);
  return result;
}

function numberValue(value: unknown, label: string, maximum = 1_000_000_000_000) {
  const parsed = value == null || value === "" ? 0 : Number(value);
  if (!Number.isFinite(parsed) || parsed < 0 || parsed > maximum) {
    throw new ApiError(400, `${label} must be a non-negative number.`);
  }
  return parsed;
}

function priceCents(value: unknown, label: string) {
  const amount = numberValue(value, label, 999_999_999.99);
  const cents = Math.round(amount * 100);
  if (Math.abs(amount * 100 - cents) > 0.000001) {
    throw new ApiError(400, `${label} cannot have more than two decimal places.`);
  }
  return cents;
}

function stock(value: unknown, label: string) {
  const count = value == null || value === "" ? 0 : Number(value);
  if (!Number.isSafeInteger(count) || count < 0 || count > 1_000_000_000) {
    throw new ApiError(400, `${label} must be a non-negative whole number.`);
  }
  return count;
}

function dateValue(value: unknown, label: string) {
  const date = text(value, label, 10);
  if (!date) return null;
  const parsed = new Date(`${date}T00:00:00.000Z`);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || Number.isNaN(parsed.getTime()) || parsed.toISOString().slice(0, 10) !== date) {
    throw new ApiError(400, `${label} must be a valid date.`);
  }
  return date;
}

function canonicalStatus(value: unknown, values: string[]) {
  const result = text(value, "Status", 32, true).toLowerCase().replace(/[\s-]+/g, "_");
  if (!values.includes(result)) throw new ApiError(400, "Choose a valid status.");
  return result;
}

function escapeCsv(value: unknown) {
  let result = String(value ?? "");
  if (/^[\s]*[=+\-@]/.test(result)) result = `'${result}`;
  return `"${result.replaceAll('"', '""')}"`;
}

function csvRow(values: unknown[]) {
  return `${values.map(escapeCsv).join(",")}\r\n`;
}

function mapProfile(row: Record<string, unknown>): Session & Record<string, unknown> {
  return {
    id: String(row.id),
    name: String(row.name ?? ""),
    role: row.role as Role,
    mustChangePassword: Boolean(row.must_change_password),
    email: row.email ?? null,
    phone: row.phone ?? null,
    createdAt: row.created_at,
  };
}

async function requireSession(request: Request, route: string): Promise<Session> {
  const authorization = request.headers.get("Authorization");
  const token = authorization?.match(/^Bearer\s+(.+)$/i)?.[1];
  if (!token) throw new ApiError(401, "Please sign in again.");
  const { data: authData, error: authError } = await admin.auth.getUser(token);
  if (authError || !authData.user) throw new ApiError(401, "Please sign in again.");
  const { data: profile, error } = await admin.from("profiles").select("*").eq("id", authData.user.id).maybeSingle();
  if (error) throw error;
  if (!profile || !roles.has(profile.role)) throw new ApiError(403, "Your workspace account is not configured.");
  if (profile.must_change_password && !["/api/me", "/api/auth/change-password", "/api/setup-status"].includes(route)) {
    throw new ApiError(403, "Change your temporary password before continuing.");
  }
  return mapProfile(profile);
}

function requireWriter(session: Session) {
  if (!writerRoles.has(session.role)) throw new ApiError(403, "You do not have permission to change workspace records.");
}

function requireOwner(session: Session) {
  if (session.role !== "owner") throw new ApiError(403, "Only the workspace owner can perform this action.");
}

function checkResult<T>(result: { data: T; error: { code?: string; message: string } | null }): T {
  if (result.error) {
    if (result.error.code === "23505") throw new ApiError(409, "This change conflicts with an existing workspace record.");
    if (result.error.code === "42501") throw new ApiError(403, result.error.message);
    if (result.error.code === "P0002") throw new ApiError(404, result.error.message);
    if (result.error.code === "23514") throw new ApiError(409, result.error.message);
    if (result.error.code === "22023") throw new ApiError(400, result.error.message);
    throw result.error;
  }
  return result.data;
}

function mapPatent(row: Record<string, unknown>) {
  return {
    id: row.id, title: row.title, patentNumber: row.patent_number, owner: row.owner, category: row.category,
    status: row.status, filingDate: row.filing_date ?? "", renewalDate: row.renewal_date ?? "",
    estimatedValue: Number(row.estimated_value), description: row.description, createdAt: row.created_at, updatedAt: row.updated_at,
  };
}

function mapProduct(row: Record<string, unknown>) {
  return {
    id: row.id, name: row.name, category: row.category, description: row.description, sku: row.sku,
    price: Number(row.price_cents) / 100, stockQuantity: Number(row.stock_quantity),
    patentIds: (row.product_patents ?? []).map((link: Record<string, unknown>) => link.patent_id),
    createdAt: row.created_at, updatedAt: row.updated_at,
  };
}

function mapSupplier(row: Record<string, unknown>) {
  return {
    id: row.id, name: row.name, service: row.service, email: row.email, phone: row.phone,
    status: row.status, notes: row.notes, createdAt: row.created_at, updatedAt: row.updated_at,
  };
}

function mapCollection(row: Record<string, unknown>) {
  return {
    id: row.id, name: row.name, description: row.description, isPublic: row.is_public,
    patentIds: row.patent_ids ?? [], createdAt: row.created_at, updatedAt: row.updated_at,
  };
}

function mapSale(row: Record<string, unknown>) {
  return {
    id: row.id, receiptNumber: row.receipt_number, cashierId: row.cashier_id, customerName: row.customer_name,
    items: row.items, subtotalCents: Number(row.subtotal_cents), taxCents: Number(row.tax_cents),
    totalCents: Number(row.total_cents), amountReceivedCents: Number(row.amount_received_cents),
    changeCents: Number(row.change_cents), paymentMethod: row.payment_method, status: row.status,
    refundedAt: row.refunded_at ?? "", refundedBy: row.refunded_by, refundReason: row.refund_reason,
    createdAt: row.created_at,
  };
}

function patentGrowth(rows: Record<string, unknown>[]) {
  const now = new Date();
  const start = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 11, 1));
  const additions = new Map<string, number>();
  for (const row of rows) {
    const date = String(row.filing_date || row.created_at || "");
    const month = date.slice(0, 7);
    if (month >= start.toISOString().slice(0, 7)) additions.set(month, (additions.get(month) ?? 0) + 1);
  }
  return Array.from({ length: 12 }, (_, offset) => {
    const date = new Date(Date.UTC(start.getUTCFullYear(), start.getUTCMonth() + offset, 1));
    const month = date.toISOString().slice(0, 7);
    return { month, count: additions.get(month) ?? 0 };
  });
}

async function profilesFor(session: Session) {
  const result = await admin.from("profiles").select("*").order("created_at");
  return checkResult(result).map(mapProfile);
}

function userClient(request: Request) {
  return createClient(supabaseUrl!, anonKey!, {
    global: { headers: { Authorization: request.headers.get("Authorization") ?? "" } },
    auth: { autoRefreshToken: false, persistSession: false },
  });
}

function patentInput(body: Record<string, unknown>, previous?: Record<string, unknown>) {
  const merged = { ...previous, ...body };
  const status = canonicalStatus(merged.status || "pending", ["active", "in_review", "pending", "filed", "granted", "expiring", "expired", "rejected"]);
  return {
    title: text(merged.title, "Patent title", 200, true),
    patent_number: text(merged.patentNumber, "Patent number", 80),
    owner: text(merged.owner, "Owner", 160),
    category: text(merged.category, "Category", 100),
    status,
    filing_date: dateValue(merged.filingDate, "Filing date"),
    renewal_date: dateValue(merged.renewalDate, "Renewal date"),
    estimated_value: numberValue(merged.estimatedValue, "Estimated value"),
    description: text(merged.description, "Description", 5000),
    updated_at: new Date().toISOString(),
  };
}

function productInput(body: Record<string, unknown>, previous?: Record<string, unknown>) {
  const merged = { ...previous, ...body };
  const patentIds = merged.patentIds ?? [];
  if (!Array.isArray(patentIds) || patentIds.length > 100 || patentIds.some((id) => typeof id !== "string")) {
    throw new ApiError(400, "Patent links must be a list of patent IDs.");
  }
  if (new Set(patentIds).size !== patentIds.length) throw new ApiError(400, "A patent can only be linked once.");
  return {
    name: text(merged.name, "Product name", 200, true),
    category: text(merged.category, "Category", 100),
    description: text(merged.description, "Description", 5000),
    sku: text(merged.sku, "SKU", 64).toUpperCase(),
    price_cents: priceCents(merged.price, "Price"),
    stock_quantity: stock(merged.stockQuantity, "Stock quantity"),
    patentIds,
    updated_at: new Date().toISOString(),
  };
}

function supplierInput(body: Record<string, unknown>, previous?: Record<string, unknown>) {
  const merged = { ...previous, ...body };
  const status = canonicalStatus(merged.status || "active", ["active", "in_review", "inactive"]);
  const email = text(merged.email, "Supplier email", 254).toLowerCase();
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new ApiError(400, "Enter a valid supplier email address.");
  const rawPhone = text(merged.phone, "Supplier phone", 32);
  const phone = rawPhone.replace(/[\s().-]/g, "");
  if (phone && !/^\+[1-9]\d{6,14}$/.test(phone)) throw new ApiError(400, "Enter a supplier phone number in international format.");
  return {
    name: text(merged.name, "Supplier name", 200, true), service: text(merged.service, "Service", 120),
    email, phone, status, notes: text(merged.notes, "Notes", 5000), updated_at: new Date().toISOString(),
  };
}

function collectionInput(body: Record<string, unknown>, previous?: Record<string, unknown>) {
  const merged = { ...previous, ...body };
  const patentIds = merged.patentIds ?? [];
  if (!Array.isArray(patentIds) || patentIds.length > 100 || patentIds.some((id) => typeof id !== "string")) {
    throw new ApiError(400, "Patent links must be a list of patent IDs.");
  }
  if (new Set(patentIds).size !== patentIds.length) throw new ApiError(400, "A patent can only be linked once.");
  if (typeof merged.isPublic !== "boolean") throw new ApiError(400, "Choose whether this showroom collection is public.");
  return {
    name: text(merged.name, "Collection name", 200, true),
    description: text(merged.description, "Description", 5000),
    is_public: merged.isPublic,
    patent_ids: patentIds,
    updated_at: new Date().toISOString(),
  };
}

async function saveProduct(productId: string | null, input: ReturnType<typeof productInput>) {
  const { patentIds, ...product } = input;
  if (patentIds.length) {
    const patents = checkResult(await admin.from("patents").select("id").in("id", patentIds));
    if (patents.length !== patentIds.length) {
      throw new ApiError(400, "A linked patent no longer exists. Refresh and try again.");
    }
  }
  let row: Record<string, unknown>;
  if (productId) {
    row = checkResult(await admin.from("products").update(product).eq("id", productId).select("*").single());
    checkResult(await admin.from("product_patents").delete().eq("product_id", productId));
  } else {
    row = checkResult(await admin.from("products").insert(product).select("*").single());
  }
  if (patentIds.length) {
    checkResult(await admin.from("product_patents").insert(patentIds.map((patentId) => ({ product_id: row.id, patent_id: patentId }))));
  }
  const links = checkResult(await admin.from("product_patents").select("patent_id").eq("product_id", row.id));
  return mapProduct({ ...row, product_patents: links });
}

async function verifyPatentIds(ids: string[]) {
  if (!ids.length) return;
  const patents = checkResult(await admin.from("patents").select("id").in("id", ids));
  if (patents.length !== ids.length) {
    throw new ApiError(400, "A linked patent no longer exists. Refresh and try again.");
  }
}

async function handle(request: Request, route: string, session: Session | null) {
  const method = request.method;
  const url = new URL(request.url);

  if (route === "/api/setup-status" && method === "GET") {
    const { count, error } = await admin.from("profiles").select("id", { count: "exact", head: true }).eq("role", "owner");
    if (error) throw error;
    return json({ setupComplete: (count ?? 0) > 0 });
  }
  if (route === "/api/setup" && method === "POST") {
    if (!session) throw new ApiError(401, "Sign in to finish creating your workspace.");
    const body = await bodyJson(request);
    allowedFields(body, ["name"]);
    const profile = checkResult(await userClient(request).rpc("bootstrap_owner", { owner_name: text(body.name, "Your name", 120, true) }));
    return json({ user: mapProfile(profile), setupComplete: true }, 201);
  }
  if (route === "/api/showroom" && method === "GET") {
    const collections = checkResult(await admin.from("collections").select("*").eq("is_public", true).order("created_at"));
    const result = [];
    for (const row of collections) {
      const patents = row.patent_ids.length
        ? checkResult(await admin.from("patents").select("id, title, patent_number, category").in("id", row.patent_ids))
        : [];
      const byId = new Map(patents.map((patent: Record<string, unknown>) => [String(patent.id), patent]));
      result.push({
        name: row.name, description: row.description,
        patents: row.patent_ids.map((id: string) => byId.get(id)).filter(Boolean).map((patent: Record<string, unknown>) => ({
          title: patent.title, patentNumber: patent.patent_number, category: patent.category,
        })),
      });
    }
    return json({ collections: result });
  }
  if (!session) throw new ApiError(401, "Please sign in again.");

  if (route === "/api/me" && method === "GET") return json({ user: session });
  if (route === "/api/auth/change-password" && method === "POST") {
    const body = await bodyJson(request);
    allowedFields(body, ["newPassword"]);
    const newPassword = text(body.newPassword, "New password", 1024, true);
    if (newPassword.length < 12) throw new ApiError(400, "Use a password with at least 12 characters.");
    const { error: passwordError } = await admin.auth.admin.updateUserById(session.id, { password: newPassword });
    if (passwordError) throw passwordError;
    checkResult(await admin.from("profiles").update({ must_change_password: false }).eq("id", session.id));
    return json({ user: { ...session, mustChangePassword: false } });
  }
  if (route === "/api/settings" && method === "GET") {
    const rows = checkResult(await admin.from("settings").select("*").order("setting_key"));
    return json({ settings: Object.fromEntries(rows.map((row: Record<string, unknown>) => [row.setting_key, row.setting_value])) });
  }
  if (route === "/api/settings" && method === "PATCH") {
    requireOwner(session);
    const body = await bodyJson(request);
    allowedFields(body, ["workspaceName", "currency", "timezone", "taxRate"]);
    const updates: Record<string, unknown> = {};
    if ("workspaceName" in body) updates.workspaceName = text(body.workspaceName, "Workspace name", 120, true);
    if ("currency" in body) {
      const currency = text(body.currency, "Currency", 3, true).toUpperCase();
      if (!/^[A-Z]{3}$/.test(currency)) throw new ApiError(400, "Enter a valid three-letter currency code.");
      updates.currency = currency;
    }
    if ("timezone" in body) {
      const timezone = text(body.timezone, "Time zone", 80, true);
      try { new Intl.DateTimeFormat("en", { timeZone: timezone }); } catch { throw new ApiError(400, "Enter a valid time zone."); }
      updates.timezone = timezone;
    }
    if ("taxRate" in body) {
      const rate = Number(body.taxRate);
      if (!Number.isFinite(rate) || rate < 0 || rate > 100) throw new ApiError(400, "Tax rate must be between 0 and 100 percent.");
      updates.taxRate = Math.round(rate * 100) / 100;
    }
    for (const [setting_key, setting_value] of Object.entries(updates)) {
      checkResult(await admin.from("settings").upsert({ setting_key, setting_value }, { onConflict: "setting_key" }));
    }
    return await handle(new Request(request.url, { method: "GET", headers: request.headers }), route, session);
  }

  if (route === "/api/team" && method === "GET") {
    requireOwner(session);
    return json({ members: await profilesFor(session) });
  }
  if (route === "/api/team" && method === "POST") {
    requireOwner(session);
    const body = await bodyJson(request);
    allowedFields(body, ["name", "identifier", "role"]);
    const name = text(body.name, "Name", 120, true);
    const identifier = text(body.identifier, "Email or phone", 254, true);
    const role = text(body.role ?? "editor", "Role", 32, true);
    if (!["editor", "reviewer"].includes(role)) throw new ApiError(400, "Choose the editor or reviewer role.");
    const temporaryPassword = crypto.randomUUID() + crypto.randomUUID();
    const contact = identifier.includes("@")
      ? { email: identifier.trim().toLowerCase(), phone: undefined }
      : { email: undefined, phone: identifier.replace(/[\s().-]/g, "") };
    const { data, error } = await admin.auth.admin.createUser({
      ...contact, password: temporaryPassword, email_confirm: true, phone_confirm: true,
      user_metadata: { name },
    });
    if (error || !data.user) throw new ApiError(409, "An account with that email address or phone number already exists.");
    checkResult(await admin.from("profiles").update({ name, role, must_change_password: true }).eq("id", data.user.id));
    const profile = checkResult(await admin.from("profiles").select("*").eq("id", data.user.id).single());
    return json({ member: mapProfile(profile), temporaryPassword }, 201);
  }

  if (route === "/api/overview" && method === "GET") {
    const [patents, recent, sales, products] = await Promise.all([
      admin.from("patents").select("*"),
      admin.from("patents").select("*").order("updated_at", { ascending: false }).limit(5),
      admin.from("sales").select("total_cents,created_at,status"),
      admin.from("products").select("stock_quantity"),
    ]);
    const allPatents = checkResult(patents);
    const today = new Date().toISOString().slice(0, 10);
    const byStatus = new Map<string, number>();
    for (const patent of allPatents) byStatus.set(patent.status, (byStatus.get(patent.status) ?? 0) + 1);
    const saleRows = checkResult(sales);
    return json({
      totalPatents: allPatents.length,
      activeApplications: allPatents.filter((row) => ["pending", "filed", "in_review"].includes(row.status)).length,
      renewalsDue: allPatents.filter((row) => row.renewal_date && row.renewal_date >= today
        && row.renewal_date <= new Date(Date.now() + 90 * 86400000).toISOString().slice(0, 10)).length,
      estimatedPortfolioValue: allPatents.reduce((sum, row) => sum + Number(row.estimated_value), 0),
      byStatus: [...byStatus].map(([status, count]) => ({ status, count })),
      recentPatents: checkResult(recent).map(mapPatent),
      growth: patentGrowth(allPatents),
      todaySalesCount: saleRows.filter((row) => row.status === "completed" && row.created_at.startsWith(today)).length,
      todayRevenueCents: saleRows.filter((row) => row.status === "completed" && row.created_at.startsWith(today)
      ).reduce((sum, row) => sum + Number(row.total_cents), 0),
      lowStockCount: checkResult(products).filter((row) => Number(row.stock_quantity) <= 5).length,
    });
  }

  if (route === "/api/reports" && method === "GET") {
    const [patentRows, supplierRows, productRows, salesRows] = await Promise.all([
      admin.from("patents").select("*"), admin.from("suppliers").select("id"),
      admin.from("products").select("id,stock_quantity"), admin.from("sales").select("total_cents,created_at,status"),
    ]);
    const patents = checkResult(patentRows);
    const sales = checkResult(salesRows);
    const today = new Date().toISOString().slice(0, 10);
    const statusCounts = new Map<string, number>();
    patents.forEach((row) => statusCounts.set(row.status, (statusCounts.get(row.status) ?? 0) + 1));
    return json({
      totalPatents: patents.length,
      byStatus: [...statusCounts].map(([status, count]) => ({ status, count })),
      renewalsDue: patents.filter((row) => row.renewal_date && row.renewal_date >= today
        && row.renewal_date <= new Date(Date.now() + 90 * 86400000).toISOString().slice(0, 10)).length,
      estimatedPortfolioValue: patents.reduce((sum, row) => sum + Number(row.estimated_value), 0),
      suppliers: checkResult(supplierRows).length,
      products: checkResult(productRows).length,
      todaySalesCount: sales.filter((row) => row.status === "completed" && row.created_at.startsWith(today)).length,
      todayRevenueCents: sales.filter((row) => row.status === "completed" && row.created_at.startsWith(today)
      ).reduce((sum, row) => sum + Number(row.total_cents), 0),
      lowStockCount: checkResult(productRows).filter((row) => Number(row.stock_quantity) <= 5).length,
    });
  }

  const csvMatch = route.match(/^\/api\/(reports|sales)\.csv$/);
  if (csvMatch && method === "GET") {
    const isSales = csvMatch[1] === "sales";
    const rows = isSales
      ? checkResult(await admin.from("sales").select("*").order("created_at", { ascending: false }))
      : checkResult(await admin.from("patents").select("*").order("updated_at", { ascending: false }));
    const headers = isSales
      ? ["Receipt", "Date", "Customer", "Payment method", "Status", "Refund reason", "Items", "Subtotal", "Tax", "Total", "Cash received", "Change"]
      : ["Patent", "Patent number", "Owner", "Category", "Status", "Filing date", "Renewal date", "Estimated value", "Description"];
    let output = csvRow(headers);
    for (const row of rows) {
      output += isSales
        ? csvRow([row.receipt_number, row.created_at, row.customer_name, row.payment_method, row.status, row.refund_reason,
          row.items.map((item: Record<string, unknown>) => `${item.quantity} x ${item.name}`).join("; "),
          (Number(row.subtotal_cents) / 100).toFixed(2), (Number(row.tax_cents) / 100).toFixed(2),
          (Number(row.total_cents) / 100).toFixed(2), (Number(row.amount_received_cents) / 100).toFixed(2),
          (Number(row.change_cents) / 100).toFixed(2)])
        : csvRow([row.title, row.patent_number, row.owner, row.category, row.status, row.filing_date, row.renewal_date, row.estimated_value, row.description]);
    }
    return new Response(output, { headers: {
      "Content-Type": "text/csv; charset=utf-8",
      "Content-Disposition": `attachment; filename="anucho-${isSales ? "sales" : "patents"}.csv"`,
      "Cache-Control": "no-store",
    } });
  }

  if (route === "/api/sales" && method === "GET") {
    const [sales, products] = await Promise.all([
      admin.from("sales").select("*").order("created_at", { ascending: false }).limit(100),
      admin.from("products").select("stock_quantity"),
    ]);
    const rows = checkResult(sales);
    const today = new Date().toISOString().slice(0, 10);
    const todays = rows.filter((row) => row.status === "completed" && row.created_at.startsWith(today));
    return json({
      sales: rows.map(mapSale),
      summary: { todayCount: todays.length, todayRevenueCents: todays.reduce((sum, row) => sum + Number(row.total_cents), 0),
        lowStockCount: checkResult(products).filter((row) => Number(row.stock_quantity) <= 5).length },
    });
  }
  if (route === "/api/sales" && method === "POST") {
    requireWriter(session);
    const body = await bodyJson(request);
    allowedFields(body, ["items", "paymentMethod", "amountReceived", "customerName"]);
    if (!Array.isArray(body.items)) throw new ApiError(400, "A sale must contain between 1 and 100 products.");
    const items = body.items.map((item) => {
      if (!item || typeof item !== "object" || Array.isArray(item)) throw new ApiError(400, "Each sale item must include a product and quantity.");
      allowedFields(item as Record<string, unknown>, ["productId", "quantity"]);
      return { productId: text((item as Record<string, unknown>).productId, "Product ID", 64, true), quantity: stock((item as Record<string, unknown>).quantity, "Item quantity") };
    });
    const paymentMethod = text(body.paymentMethod, "Payment method", 16, true).toLowerCase();
    const received = paymentMethod === "cash" ? priceCents(body.amountReceived, "Amount received") : null;
    const result = await userClient(request).rpc("complete_sale", {
      sale_items: items, payment_method: paymentMethod, amount_received_cents: received,
      customer_name: text(body.customerName, "Customer name", 120),
      receipt_number: `AN-${new Date().toISOString().slice(0, 10).replaceAll("-", "")}-${crypto.randomUUID().slice(0, 6).toUpperCase()}`,
    });
    const row = checkResult(result);
    return json({ sale: mapSale(row) }, 201);
  }
  const refund = route.match(/^\/api\/sales\/([^/]+)\/refund$/);
  if (refund && method === "POST") {
    requireWriter(session);
    const body = await bodyJson(request);
    allowedFields(body, ["reason"]);
    const reason = text(body.reason, "Refund reason", 240, true);
    return json({ sale: mapSale(checkResult(await userClient(request).rpc("refund_sale", { sale_id: refund[1], reason }))) });
  }

  const resources = {
    patents: { table: "patents", key: "patent", map: mapPatent },
    products: { table: "products", key: "product", map: mapProduct },
    suppliers: { table: "suppliers", key: "supplier", map: mapSupplier },
    collections: { table: "collections", key: "collection", map: mapCollection },
  } as const;
  const resourceMatch = route.match(/^\/api\/(patents|products|suppliers|collections)(?:\/([^/]+))?$/);
  if (resourceMatch) {
    const resource = resourceMatch[1] as keyof typeof resources;
    const config = resources[resource];
    const id = resourceMatch[2] ? decodeURIComponent(resourceMatch[2]) : null;
    const map = config.map as (row: Record<string, unknown>) => Record<string, unknown>;
    if (!id && method === "GET") {
      const search = url.searchParams.get("q")?.trim();
      let query = admin.from(config.table).select(resource === "products" ? "*,product_patents(patent_id)" : "*").order("created_at", { ascending: false });
      query = query.limit(200);
      if (search) query = query.or(resource === "patents"
        ? `title.ilike.%${search}%,patent_number.ilike.%${search}%,owner.ilike.%${search}%,category.ilike.%${search}%,status.ilike.%${search}%`
        : `name.ilike.%${search}%,sku.ilike.%${search}%,category.ilike.%${search}%,description.ilike.%${search}%`);
      const rows = checkResult(await query);
      const items = rows.map(map);
      return json({ [resource]: items });
    }
    const key = config.key;
    if (!id && method === "POST") {
      requireWriter(session);
      const body = await bodyJson(request);
      const fields = resource === "patents" ? ["title", "patentNumber", "owner", "category", "status", "filingDate", "renewalDate", "estimatedValue", "description"]
        : resource === "products" ? ["name", "category", "description", "sku", "price", "stockQuantity", "patentIds"]
          : resource === "suppliers" ? ["name", "service", "email", "phone", "status", "notes"] : ["name", "description", "isPublic", "patentIds"];
      allowedFields(body, fields);
      let saved: Record<string, unknown>;
      if (resource === "products") {
        saved = await saveProduct(null, productInput(body));
      } else {
        let input: Record<string, unknown>;
        if (resource === "patents") {
          input = patentInput({ ...body, owner: body.owner || session.name });
        } else if (resource === "suppliers") {
          input = supplierInput(body);
        } else {
          const collection = collectionInput(body);
          await verifyPatentIds(collection.patent_ids);
          input = collection;
        }
        const row = checkResult(await admin.from(config.table).insert(input).select("*").single());
        saved = map(row);
      }
      return json({ [key]: saved }, 201);
    }
    if (id && method === "GET") {
      const query = admin.from(config.table).select(resource === "products" ? "*,product_patents(patent_id)" : "*").eq("id", id).maybeSingle();
      const row = checkResult(await query);
      if (!row) throw new ApiError(404, `${resource.slice(0, -1)} not found.`);
      return json({ [key]: map(row) });
    }
    if (id && method === "DELETE") {
      requireWriter(session);
      checkResult(await admin.from(config.table).delete().eq("id", id));
      return json({ ok: true });
    }
    if (id && ["PUT", "PATCH"].includes(method)) {
      requireWriter(session);
      const current = checkResult(await admin.from(config.table).select(resource === "products" ? "*,product_patents(patent_id)" : "*").eq("id", id).maybeSingle());
      if (!current) throw new ApiError(404, `${resource.slice(0, -1)} not found.`);
      const body = await bodyJson(request);
      const fields = resource === "patents" ? ["title", "patentNumber", "owner", "category", "status", "filingDate", "renewalDate", "estimatedValue", "description"]
        : resource === "products" ? ["name", "category", "description", "sku", "price", "stockQuantity", "patentIds"]
          : resource === "suppliers" ? ["name", "service", "email", "phone", "status", "notes"] : ["name", "description", "isPublic", "patentIds"];
      allowedFields(body, fields);
      let saved: Record<string, unknown>;
      if (resource === "products") {
        saved = await saveProduct(id, productInput(body, map(current)));
      } else {
        const previous = map(current);
        let input: Record<string, unknown>;
        if (resource === "patents") {
          input = patentInput(body, previous);
        } else if (resource === "suppliers") {
          input = supplierInput(body, previous);
        } else {
          const collection = collectionInput(body, previous);
          await verifyPatentIds(collection.patent_ids);
          input = collection;
        }
        saved = map(checkResult(await admin.from(config.table).update(input).eq("id", id).select("*").single()));
      }
      return json({ [key]: saved });
    }
  }

  if (route === "/api/collections" && method === "GET") {
    const rows = checkResult(await admin.from("collections").select("*").order("created_at", { ascending: false }));
    return json({ collections: rows.map(mapCollection) });
  }
  if (route === "/api/team" && method === "GET") {
    requireOwner(session);
    return json({ members: await profilesFor(session) });
  }
  const resetMember = route.match(/^\/api\/team\/([^/]+)\/reset-password$/);
  if (resetMember && method === "POST") {
    requireOwner(session);
    const memberId = decodeURIComponent(resetMember[1]);
    if (memberId === session.id) throw new ApiError(409, "Use Settings to change your own password.");
    const temporaryPassword = crypto.randomUUID() + crypto.randomUUID();
    const { data, error } = await admin.auth.admin.updateUserById(memberId, { password: temporaryPassword });
    if (error || !data.user) throw new ApiError(404, "Team member not found.");
    checkResult(await admin.from("profiles").update({ must_change_password: true }).eq("id", memberId));
    const profile = checkResult(await admin.from("profiles").select("*").eq("id", memberId).single());
    return json({ member: mapProfile(profile), temporaryPassword });
  }
  const memberMatch = route.match(/^\/api\/team\/([^/]+)$/);
  if (memberMatch && method === "PATCH") {
    requireOwner(session);
    const memberId = decodeURIComponent(memberMatch[1]);
    const body = await bodyJson(request);
    allowedFields(body, ["role", "name"]);
    const current = checkResult(await admin.from("profiles").select("*").eq("id", memberId).maybeSingle());
    if (!current) throw new ApiError(404, "Team member not found.");
    const name = body.name === undefined ? current.name : text(body.name, "Name", 120, true);
    const role = body.role === undefined ? current.role : text(body.role, "Role", 32, true);
    if (!roles.has(role as Role) || (role === "owner" && session.id !== memberId)) {
      throw new ApiError(400, "Only the current owner can retain the owner role.");
    }
    if (current.role === "owner" && role !== "owner") {
      const { count, error } = await admin.from("profiles").select("id", { count: "exact", head: true }).eq("role", "owner").neq("id", memberId);
      if (error) throw error;
      if (!count) throw new ApiError(409, "Transfer the owner role before changing this account.");
    }
    const updated = checkResult(await admin.from("profiles").update({ name, role }).eq("id", memberId).select("*").single());
    return json({ member: mapProfile(updated) });
  }
  if (memberMatch && method === "DELETE") {
    requireOwner(session);
    const memberId = decodeURIComponent(memberMatch[1]);
    const current = checkResult(await admin.from("profiles").select("role").eq("id", memberId).maybeSingle());
    if (!current) throw new ApiError(404, "Team member not found.");
    if (memberId === session.id || current.role === "owner") throw new ApiError(409, "The workspace owner cannot be removed.");
    const { error } = await admin.auth.admin.deleteUser(memberId);
    if (error) throw error;
    return json({ ok: true });
  }
  throw new ApiError(404, "Page or API route not found.");
}

Deno.serve(async (request) => {
  const origin = request.headers.get("Origin");
  const corsOrigin = origin && allowedOrigins.has(origin) ? origin : "";
  const corsHeaders = {
    ...(corsOrigin ? { "Access-Control-Allow-Origin": corsOrigin, "Vary": "Origin" } : {}),
    "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
    "Access-Control-Allow-Methods": "GET, POST, PATCH, PUT, DELETE, OPTIONS",
    "Access-Control-Expose-Headers": "Content-Disposition",
    "X-Content-Type-Options": "nosniff",
  };
  try {
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
    ensureAllowedOrigin(request);
    const pathname = new URL(request.url).pathname;
    const functionPrefix = "/functions/v1/api";
    const route = pathname.startsWith(functionPrefix) ? pathname.slice(functionPrefix.length) : pathname;
    const session = ["/api/showroom", "/api/setup-status", "/api/setup"].includes(route)
      ? await requireSession(request, route).catch((error) => {
        if (route === "/api/showroom" || route === "/api/setup-status") return null;
        throw error;
      })
      : await requireSession(request, route);
    const response = await handle(request, route, session);
    const headers = new Headers(response.headers);
    for (const [key, value] of Object.entries(corsHeaders)) headers.set(key, value);
    return new Response(response.body, { status: response.status, headers });
  } catch (error) {
    const status = error instanceof ApiError ? error.status : 500;
    const message = error instanceof Error ? error.message : "An unexpected server error occurred.";
    if (!(error instanceof ApiError)) console.error("[ANUCHO API]", error);
    const headers = new Headers(corsHeaders);
    return json({ error: status === 500 ? "An unexpected server error occurred." : message }, status, headers);
  }
});
