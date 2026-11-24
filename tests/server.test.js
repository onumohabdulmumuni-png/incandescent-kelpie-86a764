import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer as createProbe } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createServer } from "../server.js";

async function startTestServer(t) {
  const directory = mkdtempSync(join(tmpdir(), "anucho-test-"));
  const probe = createProbe();
  probe.listen(0, "127.0.0.1");
  await once(probe, "listening");
  const { port } = probe.address();
  await new Promise((resolve, reject) => probe.close((error) => error ? reject(error) : resolve()));

  const origin = `http://127.0.0.1:${port}`;
  const databasePath = join(directory, "anucho-test.db");
  let service;
  async function openService() {
    service = createServer({ databasePath, origin, host: "127.0.0.1", port });
    service.server.listen(port, "127.0.0.1");
    await once(service.server, "listening");
  }
  await openService();

  t.after(async () => {
    if (service.server.listening) {
      await new Promise((resolve, reject) => service.server.close((error) => error ? reject(error) : resolve()));
    }
    service.close();
    rmSync(directory, { recursive: true, force: true });
  });

  async function request(path, { method = "GET", body, cookie } = {}) {
    const headers = {};
    if (!["GET", "HEAD"].includes(method)) {
      headers.Origin = origin;
      headers["Content-Type"] = "application/json";
    }
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
    }
    if (cookie) {
      headers.Cookie = cookie;
    }
    let response;
    try {
      response = await fetch(`${origin}${path}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch (error) {
      throw new Error(`${method} ${path} did not reach the ANUCHO test server.`, { cause: error });
    }
    const contentType = response.headers.get("content-type") ?? "";
    const data = contentType.includes("application/json") ? await response.json() : await response.text();
    const cookieHeader = response.headers.get("set-cookie");
    const sessionCookie = cookieHeader?.match(/anucho_session=[^;]*/)?.[0] ?? null;
    return { response, data, sessionCookie };
  }

  return { request, origin, databasePath };
}

test("ANUCHO persists workspace records, protects sessions, and scopes the public showroom", async (t) => {
  const { request, origin, databasePath } = await startTestServer(t);

  const setupStatus = await request("/api/setup-status");
  assert.deepEqual(setupStatus.data, { setupComplete: false });
  const crossOrigin = await fetch(`${origin}/api/setup`, {
    method: "POST",
    headers: { Origin: "https://attacker.example", "Content-Type": "application/json" },
    body: JSON.stringify({ name: "Intruder", identifier: "intruder@example.com", password: "Asecurepassword123!" }),
  });
  assert.equal(crossOrigin.status, 403);

  const setup = await request("/api/setup", {
    method: "POST",
    body: { name: "Jordan Davis", identifier: "jordan@example.com", password: "Asecurepassword123!" },
  });
  assert.equal(setup.response.status, 201);
  assert.equal(setup.data.user.role, "owner");
  assert.match(setup.response.headers.get("set-cookie"), /HttpOnly; SameSite=Strict/);
  const ownerCookie = setup.sessionCookie;

  assert.equal((await request("/api/setup", {
    method: "POST",
    body: { name: "Second Owner", identifier: "second@example.com", password: "Asecurepassword123!" },
  })).response.status, 409);

  const anonymous = await request("/api/patents", {
    method: "POST",
    body: { title: "Not signed in" },
  });
  assert.equal(anonymous.response.status, 401);
  assert.equal((await request("/api/events")).response.status, 401);

  const newPassword = "EvenMoreSecurePassword456!";
  const login = await request("/api/auth/login", {
    method: "POST",
    body: { identifier: "JORDAN@example.com", password: "Asecurepassword123!", rememberMe: true },
  });
  assert.equal(login.response.status, 200);
  assert.match(login.response.headers.get("set-cookie"), /Max-Age=2592000/);

  const badLogin = await request("/api/auth/login", {
    method: "POST",
    body: { identifier: "jordan@example.com", password: "wrong-password" },
  });
  assert.equal(badLogin.response.status, 401);
  assert.equal(badLogin.data.error, "The email, phone number or password is incorrect.");

  const reauth = await request("/api/auth/reauth", {
    method: "POST",
    cookie: ownerCookie,
    body: { password: "Asecurepassword123!" },
  });
  assert.equal(reauth.response.status, 200);

  const options = await request("/api/auth/passkeys/registration/options", {
    method: "POST",
    cookie: ownerCookie,
    body: {},
  });
  assert.equal(options.response.status, 200);
  assert.equal(options.data.rp.id, "127.0.0.1");
  assert.ok(options.data.challenge);
  assert.equal(options.data.authenticatorSelection.userVerification, "required");

  const creation = await request("/api/patents", {
    method: "POST",
    cookie: ownerCookie,
    body: {
      title: "=2+2",
      patentNumber: "US-ANU-001",
      owner: "ANUCHO",
      category: "Clean technology",
      status: "pending",
      renewalDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10),
      estimatedValue: 125000,
      description: "Energy-storage portfolio entry",
    },
  });
  assert.equal(creation.response.status, 201);
  const patentId = creation.data.patent.id;
  assert.equal(creation.data.patent.estimatedValue, 125000);

  const invalidPatent = await request("/api/patents", {
    method: "POST",
    cookie: ownerCookie,
    body: { title: "Invalid patent", status: "not-a-status" },
  });
  assert.equal(invalidPatent.response.status, 400);

  const search = await request("/api/patents?q=US-ANU-001", { cookie: ownerCookie });
  assert.equal(search.response.status, 200);
  assert.equal(search.data.patents.length, 1);
  assert.equal(search.data.patents[0].id, patentId);

  const product = await request("/api/products", {
    method: "POST",
    cookie: ownerCookie,
    body: {
      name: "Energy storage system",
      category: "Clean technology",
      sku: "energy-001",
      price: 12.5,
      stockQuantity: 10,
      patentIds: [patentId],
    },
  });
  assert.equal(product.response.status, 201);
  assert.deepEqual(product.data.product.patentIds, [patentId]);
  assert.equal(product.data.product.sku, "ENERGY-001");
  assert.equal(product.data.product.price, 12.5);
  assert.equal(product.data.product.stockQuantity, 10);

  const duplicateSku = await request("/api/products", {
    method: "POST",
    cookie: ownerCookie,
    body: { name: "Duplicate SKU", sku: "energy-001", price: 4, stockQuantity: 2 },
  });
  assert.equal(duplicateSku.response.status, 409);
  const invalidPrice = await request("/api/products", {
    method: "POST",
    cookie: ownerCookie,
    body: { name: "Invalid price", price: 1.234, stockQuantity: 2 },
  });
  assert.equal(invalidPrice.response.status, 400);

  const taxSettings = await request("/api/settings", {
    method: "PATCH",
    cookie: ownerCookie,
    body: { taxRate: 8.25 },
  });
  assert.equal(taxSettings.response.status, 200);
  assert.equal(taxSettings.data.settings.taxRate, 8.25);

  const insufficientStock = await request("/api/sales", {
    method: "POST",
    cookie: ownerCookie,
    body: {
      items: [{ productId: product.data.product.id, quantity: 11 }],
      paymentMethod: "cash",
      amountReceived: 200,
    },
  });
  assert.equal(insufficientStock.response.status, 409);
  const insufficientPayment = await request("/api/sales", {
    method: "POST",
    cookie: ownerCookie,
    body: {
      items: [{ productId: product.data.product.id, quantity: 2 }],
      paymentMethod: "cash",
      amountReceived: 20,
    },
  });
  assert.equal(insufficientPayment.response.status, 400);

  const sale = await request("/api/sales", {
    method: "POST",
    cookie: ownerCookie,
    body: {
      items: [{ productId: product.data.product.id, quantity: 2 }],
      paymentMethod: "cash",
      amountReceived: 30,
      customerName: "Casey Customer",
    },
  });
  assert.equal(sale.response.status, 201);
  assert.equal(sale.data.sale.subtotalCents, 2500);
  assert.equal(sale.data.sale.taxCents, 206);
  assert.equal(sale.data.sale.totalCents, 2706);
  assert.equal(sale.data.sale.changeCents, 294);
  assert.equal(sale.data.sale.customerName, "Casey Customer");
  const afterSaleProducts = await request("/api/products", { cookie: ownerCookie });
  assert.equal(afterSaleProducts.data.products.find((item) => item.id === product.data.product.id).stockQuantity, 8);

  const saleHistory = await request("/api/sales", { cookie: ownerCookie });
  assert.equal(saleHistory.data.sales.length, 1);
  assert.equal(saleHistory.data.summary.todayCount, 1);
  assert.equal(saleHistory.data.summary.todayRevenueCents, 2706);
  const salesCsv = await request("/api/sales.csv", { cookie: ownerCookie });
  assert.equal(salesCsv.response.status, 200);
  assert.match(salesCsv.data, /AN-\d{8}-[A-F0-9]{6}/);

  const missingRefundReason = await request(`/api/sales/${sale.data.sale.id}/refund`, {
    method: "POST",
    cookie: ownerCookie,
    body: {},
  });
  assert.equal(missingRefundReason.response.status, 400);
  const refund = await request(`/api/sales/${sale.data.sale.id}/refund`, {
    method: "POST",
    cookie: ownerCookie,
    body: { reason: "Customer returned item" },
  });
  assert.equal(refund.response.status, 200);
  assert.equal(refund.data.sale.status, "refunded");
  assert.equal(refund.data.sale.refundReason, "Customer returned item");
  assert.ok(refund.data.sale.refundedAt);
  const duplicateRefund = await request(`/api/sales/${sale.data.sale.id}/refund`, {
    method: "POST",
    cookie: ownerCookie,
    body: { reason: "Duplicate return" },
  });
  assert.equal(duplicateRefund.response.status, 409);
  assert.equal(
    (await request("/api/products", { cookie: ownerCookie })).data.products
      .find((item) => item.id === product.data.product.id).stockQuantity,
    10,
  );
  const refundedHistory = await request("/api/sales", { cookie: ownerCookie });
  assert.equal(refundedHistory.data.sales[0].status, "refunded");
  assert.equal(refundedHistory.data.summary.todayCount, 0);
  assert.equal(refundedHistory.data.summary.todayRevenueCents, 0);
  const refundedReports = await request("/api/reports", { cookie: ownerCookie });
  assert.equal(refundedReports.data.todaySalesCount, 0);
  assert.equal(refundedReports.data.todayRevenueCents, 0);

  const supplier = await request("/api/suppliers", {
    method: "POST",
    cookie: ownerCookie,
    body: { name: "Northstar IP Counsel", service: "Patent prosecution", email: "hello@northstar.example" },
  });
  assert.equal(supplier.response.status, 201);

  const privateCollection = await request("/api/collections", {
    method: "POST",
    cookie: ownerCookie,
    body: { name: "Internal review", description: "Private portfolio review", isPublic: false, patentIds: [patentId] },
  });
  assert.equal(privateCollection.response.status, 201);
  const publicCollection = await request("/api/collections", {
    method: "POST",
    cookie: ownerCookie,
    body: { name: "Featured innovation", description: "Selected for our showroom", isPublic: true, patentIds: [patentId] },
  });
  assert.equal(publicCollection.response.status, 201);

  const showroom = await request("/api/showroom");
  assert.equal(showroom.response.status, 200);
  assert.deepEqual(showroom.data.collections.map((item) => item.name), ["Featured innovation"]);
  assert.deepEqual(showroom.data.collections[0].patents, [{
    title: "=2+2",
    patent_number: "US-ANU-001",
    category: "Clean technology",
  }]);
  assert.equal("estimatedValue" in showroom.data.collections[0].patents[0], false);
  assert.equal("owner" in showroom.data.collections[0].patents[0], false);

  const overview = await request("/api/overview", { cookie: ownerCookie });
  assert.equal(overview.data.totalPatents, 1);
  assert.equal(overview.data.estimatedPortfolioValue, 125000);
  assert.equal(overview.data.renewalsDue, 1);
  assert.equal(overview.data.growth.length, 12);

  const reports = await request("/api/reports", { cookie: ownerCookie });
  assert.equal(reports.data.products, 1);
  assert.equal(reports.data.suppliers, 1);
  assert.equal(reports.data.todaySalesCount, 0);
  assert.equal(reports.data.todayRevenueCents, 0);
  const csv = await request("/api/reports.csv", { cookie: ownerCookie });
  assert.equal(csv.response.status, 200);
  assert.match(csv.data, /"'=2\+2"/);

  const updatedSettings = await request("/api/settings", {
    method: "PATCH",
    cookie: ownerCookie,
    body: { workspaceName: "ANUCHO Patents", currency: "EUR", timezone: "Europe/London", taxRate: 8.25 },
  });
  assert.equal(updatedSettings.response.status, 200);
  assert.equal(updatedSettings.data.settings.workspaceName, "ANUCHO Patents");

  const member = await request("/api/team", {
    method: "POST",
    cookie: ownerCookie,
    body: { name: "Morgan Kim", identifier: "morgan@example.com", role: "reviewer" },
  });
  assert.equal(member.response.status, 201);
  assert.equal(member.data.member.mustChangePassword, true);
  assert.equal(typeof member.data.temporaryPassword, "string");

  const reviewerLogin = await request("/api/auth/login", {
    method: "POST",
    body: { identifier: "morgan@example.com", password: member.data.temporaryPassword },
  });
  assert.equal(reviewerLogin.response.status, 200);
  const reviewerCookie = reviewerLogin.sessionCookie;
  assert.equal((await request("/api/patents", { cookie: reviewerCookie })).response.status, 403);

  const passwordChange = await request("/api/auth/change-password", {
    method: "POST",
    cookie: reviewerCookie,
    body: { currentPassword: member.data.temporaryPassword, newPassword },
  });
  assert.equal(passwordChange.response.status, 200);
  assert.equal(passwordChange.data.user.mustChangePassword, false);

  const eventResponse = await fetch(`${origin}/api/events`, { headers: { Cookie: reviewerCookie } });
  assert.equal(eventResponse.status, 200);
  assert.match(eventResponse.headers.get("content-type"), /text\/event-stream/);
  const eventReader = eventResponse.body.getReader();
  const decoder = new TextDecoder();
  try {
    const readyEvent = await eventReader.read();
    assert.match(decoder.decode(readyEvent.value), /event: ready/);
    const updatedProduct = await request(`/api/products/${product.data.product.id}`, {
      method: "PATCH",
      cookie: ownerCookie,
      body: { category: "Retail" },
    });
    assert.equal(updatedProduct.response.status, 200);
    let timeout;
    const eventChunk = await Promise.race([
      eventReader.read(),
      new Promise((_, reject) => {
        timeout = setTimeout(() => reject(new Error("Timed out waiting for the live workspace event.")), 3000);
      }),
    ]);
    clearTimeout(timeout);
    assert.match(decoder.decode(eventChunk.value), /"resources":\["products"\]/);
  } finally {
    await eventReader.cancel();
  }

  assert.equal((await request("/api/patents", { cookie: reviewerCookie })).response.status, 200);
  const deniedWrite = await request("/api/patents", {
    method: "POST",
    cookie: reviewerCookie,
    body: { title: "Reviewer cannot add patents", status: "pending" },
  });
  assert.equal(deniedWrite.response.status, 403);
  const deniedSale = await request("/api/sales", {
    method: "POST",
    cookie: reviewerCookie,
    body: { items: [{ productId: product.data.product.id, quantity: 1 }], paymentMethod: "card" },
  });
  assert.equal(deniedSale.response.status, 403);

  const removed = await request(`/api/team/${member.data.member.id}`, {
    method: "DELETE",
    cookie: ownerCookie,
  });
  assert.equal(removed.response.status, 200);
  assert.equal((await request("/api/auth/logout", { method: "POST", cookie: reviewerCookie, body: {} })).response.status, 200);

  const resetMember = await request("/api/team", {
    method: "POST",
    cookie: ownerCookie,
    body: { name: "Alex Lee", identifier: "alex@example.com", role: "editor" },
  });
  assert.equal(resetMember.response.status, 201);
  const initialMemberLogin = await request("/api/auth/login", {
    method: "POST",
    body: { identifier: "alex@example.com", password: resetMember.data.temporaryPassword },
  });
  const reset = await request(`/api/team/${resetMember.data.member.id}/reset-password`, {
    method: "POST",
    cookie: ownerCookie,
    body: {},
  });
  assert.equal(reset.response.status, 200);
  assert.equal((await request("/api/me", { cookie: initialMemberLogin.sessionCookie })).response.status, 401);
  assert.equal((await request("/api/auth/login", {
    method: "POST",
    body: { identifier: "alex@example.com", password: resetMember.data.temporaryPassword },
  })).response.status, 401);
  assert.equal((await request("/api/auth/login", {
    method: "POST",
    body: { identifier: "alex@example.com", password: reset.data.temporaryPassword },
  })).response.status, 200);

  const phoneMember = await request("/api/team", {
    method: "POST",
    cookie: ownerCookie,
    body: { name: "Taylor Morgan", identifier: "+12025550144", role: "editor" },
  });
  assert.equal(phoneMember.response.status, 201);
  const phoneLogin = await request("/api/auth/login", {
    method: "POST",
    body: { identifier: "+1 (202) 555-0144", password: phoneMember.data.temporaryPassword },
  });
  assert.equal(phoneLogin.response.status, 200);
  assert.equal(phoneLogin.data.user.phone, "+12025550144");

  const loggedOut = await request("/api/auth/logout", { method: "POST", cookie: ownerCookie, body: {} });
  assert.equal(loggedOut.response.status, 200);
  assert.equal((await request("/api/me", { cookie: ownerCookie })).response.status, 401);

  const reopenedDatabase = new DatabaseSync(databasePath);
  assert.equal(reopenedDatabase.prepare("SELECT COUNT(*) AS count FROM patents").get().count, 1);
  assert.equal(
    reopenedDatabase.prepare("SELECT patent_number FROM patents LIMIT 1").get().patent_number,
    "US-ANU-001",
  );
  reopenedDatabase.close();
});

test("migrates existing product tables without changing stored products", (t) => {
  const directory = mkdtempSync(join(tmpdir(), "anucho-migration-"));
  const databasePath = join(directory, "legacy.db");
  const legacyDatabase = new DatabaseSync(databasePath);
  legacyDatabase.exec(`
    CREATE TABLE products (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      category TEXT NOT NULL DEFAULT '',
      description TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    ) STRICT;
    INSERT INTO products (id, name, category, description, created_at, updated_at)
    VALUES ('legacy-product', 'Saved product', 'Tools', '', '2025-01-01', '2025-01-01');
  `);
  legacyDatabase.close();
  t.after(() => rmSync(directory, { recursive: true, force: true }));

  const service = createServer({ databasePath, origin: "http://127.0.0.1:3000", host: "127.0.0.1", port: 0 });
  try {
    const columns = service.database.prepare("PRAGMA table_info(products)").all().map((column) => column.name);
    assert.ok(columns.includes("sku"));
    assert.ok(columns.includes("price_cents"));
    assert.ok(columns.includes("stock_quantity"));
    const product = service.database.prepare("SELECT name, price_cents, stock_quantity FROM products WHERE id = ?").get("legacy-product");
    assert.equal(product.name, "Saved product");
    assert.equal(product.price_cents, 0);
    assert.equal(product.stock_quantity, 0);
  } finally {
    service.close();
  }
});
