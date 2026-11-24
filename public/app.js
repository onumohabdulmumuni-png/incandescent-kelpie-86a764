import { apiUrl, supabase, supabaseConfigured } from "./supabase.js";

const loginScreen = document.getElementById("loginScreen");
const appShell = document.getElementById("appShell");
const pageContent = document.getElementById("pageContent");
const loginForm = document.getElementById("loginForm");
const authError = document.getElementById("authError");
const recordDialog = document.getElementById("recordDialog");
const dialogFields = document.getElementById("dialogFields");
const dialogForm = document.getElementById("recordForm");
const dialogSubmit = document.getElementById("dialogSubmit");
const toast = document.getElementById("toast");
const state = {
  user: null,
  page: "POS",
  pageRequest: 0,
  setup: false,
  mode: "email",
  search: "",
  currency: "USD",
  patents: [],
  products: [],
  cart: new Map(),
  posSearch: "",
  posCategory: "All items",
  paymentMethod: "cash",
  amountReceived: "",
  customerName: "",
  sales: [],
  salesSummary: { todayCount: 0, todayRevenueCents: 0, lowStockCount: 0 },
  suppliers: [],
  collections: [],
  members: [],
  dashboard: null,
  toastTimer: null,
  searchTimer: null,
  liveEvents: null,
  pendingLiveRefresh: false,
  passwordChangeRequired: false,
};

const pageDescriptions = {
  POS: "Ring up products, take payment and keep stock up to date.",
  Sales: "Review completed transactions and reprint customer receipts.",
  Overview: "Your store and patent portfolio, in one clear view.",
  Inventory: "Track patent records, filing status and important renewal dates.",
  Products: "Manage sellable products, prices, barcodes and on-hand stock.",
  Suppliers: "Keep collaborators and patent service providers organized.",
  Reports: "See your sales, stock and patent portfolio at a glance.",
  Management: "Manage team access and workspace roles.",
  Showroom: "Choose which patent collections to present to your audience.",
  Settings: "Configure store preferences, tax and sign-in options.",
};

const patentStatuses = [
  ["pending", "Pending"],
  ["in_review", "In review"],
  ["filed", "Filed"],
  ["granted", "Granted"],
  ["active", "Active"],
  ["expiring", "Expiring"],
  ["expired", "Expired"],
  ["rejected", "Rejected"],
];
const supplierStatuses = [["active", "Active"], ["in_review", "In review"], ["inactive", "Inactive"]];
const statusColors = {
  granted: "#164c3b",
  active: "#78a88a",
  in_review: "#687caf",
  pending: "#d3b46e",
  filed: "#a6c76c",
  expiring: "#d77063",
  expired: "#b45d56",
  rejected: "#a39088",
  other: "#e8ece8",
};

const pagesByLiveResource = {
  patents: ["Overview", "Inventory", "Products", "Showroom", "Reports"],
  products: ["POS", "Products", "Inventory", "Overview", "Reports"],
  sales: ["POS", "Sales", "Overview", "Reports"],
  suppliers: ["Suppliers", "Reports"],
  collections: ["Showroom"],
  team: ["Management"],
  settings: ["POS", "Sales", "Overview", "Reports", "Settings"],
};

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]);
}

function showRequiredPasswordPage() {
  state.passwordChangeRequired = true;
  document.querySelectorAll(".nav-item[data-page]").forEach((item) => { item.disabled = true; });
  document.getElementById("crumbPage").textContent = "Change password";
  pageContent.innerHTML = `<div class="page-title-row"><div><h1>Choose a new password</h1><p>Your workspace owner created a temporary sign-in. Update the password before accessing any records.</p></div></div>
    <section class="panel"><div class="panel-heading"><div><h3>Secure your account</h3><p>Your temporary password will no longer work after this change.</p></div></div>
      <button class="action-button strong" data-action="change-password">Set a new password</button></section>`;
}

function showToast(message) {
  toast.textContent = message;
  toast.classList.remove("hidden");
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => toast.classList.add("hidden"), 4200);
}

function showAuthError(message) {
  authError.textContent = message;
  authError.classList.remove("hidden");
}

function clearAuthError() {
  authError.textContent = "";
  authError.classList.add("hidden");
}

function showLogin() {
  state.user = null;
  if (state.liveEvents) {
    supabase?.removeChannel(state.liveEvents);
  }
  state.liveEvents = null;
  state.cart.clear();
  appShell.classList.add("hidden");
  loginScreen.classList.remove("hidden");
  clearAuthError();
  document.getElementById("password").value = "";
}

function reconcileCartProducts() {
  for (const [id, item] of state.cart) {
    const updatedProduct = state.products.find((product) => product.id === id);
    if (updatedProduct) {
      state.cart.set(id, { ...item, product: updatedProduct });
    }
  }
}

function connectLiveUpdates() {
  if (!supabase) {
    return;
  }
  if (state.liveEvents) {
    supabase.removeChannel(state.liveEvents);
  }
  const resourcesByTable = {
    patents: ["patents"],
    products: ["products", "product_patents"],
    suppliers: ["suppliers"],
    collections: ["collections"],
    sales: ["sales"],
    settings: ["settings"],
    team: ["profiles"],
  };
  const channel = supabase.channel(`workspace-${state.user.id}`);
  for (const [resource, tables] of Object.entries(resourcesByTable)) {
    for (const table of tables) {
      channel.on("postgres_changes", { event: "*", schema: "public", table }, () => {
        if (pagesByLiveResource[resource]?.includes(state.page)) {
          requestLiveRefresh();
        }
      });
    }
  }
  let hasConnected = false;
  state.liveEvents = channel.subscribe((status) => {
    if (status === "SUBSCRIBED") {
      if (hasConnected) requestLiveRefresh();
      hasConnected = true;
    } else if (status === "CHANNEL_ERROR" || status === "TIMED_OUT") {
      showToast("Live updates are temporarily unavailable. Refresh to see the latest changes.");
    }
  });
}

function requestLiveRefresh() {
  if (recordDialog.open) {
    state.pendingLiveRefresh = true;
    return;
  }
  renderPage(state.page);
}

recordDialog.addEventListener("close", () => {
  if (state.pendingLiveRefresh) {
    state.pendingLiveRefresh = false;
    renderPage(state.page);
  }
});

async function api(path, options = {}) {
  if (!supabaseConfigured || !supabase) {
    throw new Error("Supabase is not configured. Set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY before building.");
  }
  const headers = new Headers(options.headers || {});
  const method = options.method || "GET";
  const { data: sessionData } = await supabase.auth.getSession();
  const request = { method, headers };
  headers.set("apikey", import.meta.env.VITE_SUPABASE_ANON_KEY);
  if (sessionData.session?.access_token) {
    headers.set("Authorization", `Bearer ${sessionData.session.access_token}`);
  }
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    headers.set("Content-Type", "application/json");
  }
  if (options.body !== undefined) {
    headers.set("Content-Type", "application/json");
    request.body = JSON.stringify(options.body);
  }
  const response = await fetch(`${apiUrl}${path}`, request);
  const contentType = response.headers.get("content-type") || "";
  const data = contentType.includes("application/json") ? await response.json() : await response.text();
  if (!response.ok) {
    if (response.status === 401 && appShell && !appShell.classList.contains("hidden")) {
      await supabase.auth.signOut();
      showLogin();
      showAuthError("Your session expired. Sign in again to continue.");
    }
    throw new Error(typeof data === "object" ? data.error || "The request could not be completed." : "The request could not be completed.");
  }
  return data;
}

async function downloadCsv(path) {
  if (!supabaseConfigured || !supabase) {
    throw new Error("Supabase is not configured.");
  }
  const { data: sessionData } = await supabase.auth.getSession();
  const headers = new Headers({ apikey: import.meta.env.VITE_SUPABASE_ANON_KEY });
  if (sessionData.session?.access_token) headers.set("Authorization", `Bearer ${sessionData.session.access_token}`);
  const response = await fetch(`${apiUrl}${path}`, { headers });
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(data.error || "The export could not be downloaded.");
  }
  const blob = await response.blob();
  const disposition = response.headers.get("content-disposition") || "";
  const filename = disposition.match(/filename="([^"]+)"/)?.[1] || "anucho-export.csv";
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  link.click();
  URL.revokeObjectURL(link.href);
}

function setAuthMode(mode) {
  state.mode = mode;
  const identity = document.getElementById("identity");
  const label = document.getElementById("identityLabel");
  const isPhone = mode === "phone";
  label.textContent = isPhone ? "Phone number" : "Email address";
  identity.type = isPhone ? "tel" : "email";
  identity.placeholder = isPhone ? "+1 (555) 000-0000" : "you@company.com";
  identity.autocomplete = isPhone ? "tel" : "username";
  document.querySelectorAll(".auth-tab").forEach((tab) => {
    const selected = tab.dataset.mode === mode;
    tab.classList.toggle("active", selected);
    tab.setAttribute("aria-selected", String(selected));
  });
}

function setSetupMode(isSetup) {
  state.setup = isSetup;
  loginScreen.classList.toggle("is-setup", isSetup);
  document.getElementById("authTitle").textContent = isSetup ? "Create your workspace" : "Welcome back";
  document.getElementById("authDescription").textContent = isSetup
    ? "Create the secure owner account for your new sales workspace."
    : "Sign in to your ANUCHO sales workspace.";
  document.getElementById("authSubmit").textContent = isSetup ? "Create secure workspace" : "Sign in to ANUCHO";
  document.getElementById("loginNote").innerHTML = isSetup
    ? "The first account created will become the workspace owner. Use a strong password."
    : "Secure Supabase sign-in · Your team workspace is protected by account roles.";
  document.getElementById("password").autocomplete = isSetup ? "new-password" : "current-password";
  setAuthMode(state.mode);
}

function displayUser(user) {
  state.user = user;
  const initials = user.name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0].toUpperCase())
    .join("") || "A";
  document.querySelectorAll(".user-name").forEach((item) => { item.textContent = user.name; });
  document.querySelectorAll(".user-role").forEach((item) => { item.textContent = roleLabel(user.role); });
  document.querySelectorAll(".user-avatar").forEach((item) => { item.textContent = initials; });
  document.querySelector(".brand-name").textContent = "ANUCHO";
}

async function loadWorkspaceSettings() {
  const result = await api("/api/settings");
  state.settings = result.settings;
  state.currency = result.settings.currency || "USD";
}

function roleLabel(role) {
  return ({ owner: "Workspace owner", editor: "Editor", reviewer: "Read-only reviewer" })[role] || "Workspace member";
}

function capitalizeStatus(status) {
  return String(status || "").replaceAll("_", " ").replace(/\b[a-z]/g, (letter) => letter.toUpperCase());
}

function formatDate(value) {
  if (!value) {
    return "—";
  }
  const date = new Date(`${value.slice(0, 10)}T00:00:00`);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}

function formatMoney(value) {
  try {
    return new Intl.NumberFormat(undefined, {
      style: "currency",
      currency: state.currency,
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    }).format(Number(value || 0));
  } catch {
    return `${state.currency} ${Number(value || 0).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
  }
}

function formatMoneyCents(value) {
  return formatMoney(Number(value || 0) / 100);
}

function emptyRow(columns, message = "No records yet. Add your first record to get started.") {
  return `<tr><td colspan="${columns}"><div class="empty-note">${escapeHtml(message)}</div></td></tr>`;
}

function actionButtons(resource, record) {
  if (!["owner", "editor"].includes(state.user?.role)) {
    return "";
  }
  return `<div class="row-actions"><button type="button" data-action="edit-record" data-resource="${resource}" data-id="${escapeHtml(record.id)}">Edit</button><button type="button" class="delete" data-action="delete-record" data-resource="${resource}" data-id="${escapeHtml(record.id)}">Remove</button></div>`;
}

function patentRows(patents, showActions = false) {
  return patents.map((patent) => `<tr>
    <td><div class="patent-name">${escapeHtml(patent.title)}</div><div class="patent-id">${escapeHtml(patent.patentNumber || patent.id.slice(0, 8))}</div></td>
    <td>${escapeHtml(patent.owner)}</td>
    <td>${escapeHtml(patent.category || "—")}</td>
    <td><span class="status ${escapeHtml(patent.status)}">${escapeHtml(capitalizeStatus(patent.status))}</span></td>
    <td>${escapeHtml(formatDate(patent.renewalDate))}</td>
    ${showActions ? `<td>${actionButtons("patents", patent)}</td>` : ""}
  </tr>`).join("");
}

function patentTable(patents, { heading = "Recent patent activity", showActions = false } = {}) {
  const columns = showActions ? 6 : 5;
  return `<div class="table-panel"><div class="table-heading"><h3>${escapeHtml(heading)}</h3>${showActions
    ? `<span class="subtle">${patents.length} record${patents.length === 1 ? "" : "s"}</span>`
    : `<button data-page="Inventory">View all records →</button>`}</div>
    <div class="table-scroll"><table><thead><tr><th>Patent / application</th><th>Owner</th><th>Category</th><th>Status</th><th>Renewal</th>${showActions ? "<th>Actions</th>" : ""}</tr></thead>
    <tbody>${patents.length ? patentRows(patents, showActions) : emptyRow(columns, state.search ? "No patents match your search." : "No patents yet. Add your first record to start building your portfolio.")}</tbody></table></div></div>`;
}

function statusLegend(byStatus) {
  const total = byStatus.reduce((sum, item) => sum + item.count, 0);
  if (!total) {
    return `<div class="donut-wrap"><div class="donut" style="background:conic-gradient(#e8ece8 0 100%)"><div class="donut-inner"><strong>0</strong><span>patents</span></div></div><p class="subtle">Your status breakdown will appear when you add a patent.</p></div>`;
  }
  const segments = [];
  let position = 0;
  for (const item of byStatus) {
    const percent = item.count * 100 / total;
    const end = position + percent;
    segments.push(`${statusColors[item.status] || statusColors.other} ${position.toFixed(2)}% ${end.toFixed(2)}%`);
    position = end;
  }
  if (position < 100) {
    segments.push(`${statusColors.other} ${position.toFixed(2)}% 100%`);
  }
  const legend = byStatus.map((item) => `<div class="legend-row"><i class="legend-dot" style="background:${statusColors[item.status] || statusColors.other}"></i>${escapeHtml(capitalizeStatus(item.status))}<b>${item.count}</b></div>`).join("");
  return `<div class="donut-wrap"><div class="donut" style="background:conic-gradient(${segments.join(",")})"><div class="donut-inner"><strong>${total}</strong><span>patents</span></div></div><div class="legend">${legend}</div></div>`;
}

function growthChart(growth) {
  const counts = growth.map((month) => month.count);
  const maximum = Math.max(1, ...counts);
  const points = growth.map((month, index) => {
    const x = 40 + (545 * index / Math.max(1, growth.length - 1));
    const y = 154 - (month.count / maximum * 114);
    return { x, y, label: new Date(`${month.month}-01T00:00:00`).toLocaleDateString(undefined, { month: "short" }) };
  });
  const path = points.map((point) => `${point.x.toFixed(1)} ${point.y.toFixed(1)}`).join(" L");
  const area = points.length ? `M${points[0].x.toFixed(1)} 160 L${path} L${points[points.length - 1].x.toFixed(1)} 160 Z` : "";
  const line = points.length ? `M${path}` : "";
  const labels = points.filter((_, index) => index % 2 === 0 || index === points.length - 1)
    .map((point) => `<text x="${(point.x - 8).toFixed(1)}" y="183" class="chart-label">${escapeHtml(point.label)}</text>`).join("");
  return `<div class="chart"><svg viewBox="0 0 600 190" preserveAspectRatio="none" role="img" aria-label="Monthly patent additions">
    <defs><linearGradient id="growthFade" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="#7aaf8f" stop-opacity=".24"/><stop offset="1" stop-color="#7aaf8f" stop-opacity="0"/></linearGradient></defs>
    <line x1="38" y1="25" x2="590" y2="25" class="chart-grid"/><line x1="38" y1="70" x2="590" y2="70" class="chart-grid"/>
    <line x1="38" y1="115" x2="590" y2="115" class="chart-grid"/><line x1="38" y1="160" x2="590" y2="160" class="chart-grid"/>
    <text x="0" y="28" class="chart-label">${maximum}</text><text x="0" y="163" class="chart-label">0</text>
    <path class="chart-fill" d="${area}"/><path class="chart-line" d="${line}"/>${labels}</svg></div>`;
}

function dashboardMarkup() {
  const data = state.dashboard;
  const rows = state.patents;
  const topStats = [
    ["Total patents", data.totalPatents, "◇", "Across your workspace"],
    ["Active applications", data.activeApplications, "◷", "Pending, filed or in review"],
    ["Renewals due", data.renewalsDue, "↻", "Within the next 90 days"],
    ["Portfolio value", formatMoney(data.estimatedPortfolioValue), "↗", "Estimated patent value"],
  ];
  return `<div class="page-title-row"><div><h1>Good morning, ${escapeHtml(state.user.name.split(/\s+/)[0])}</h1><p>${escapeHtml(pageDescriptions.Overview)}</p></div>
    <div class="button-row"><a class="action-button action-link" href="#" data-action="export-reports">↓ Export report</a>${["owner", "editor"].includes(state.user.role) ? '<button class="action-button strong" data-action="add-record" data-resource="patents">＋ Add patent</button>' : ""}</div></div>
    <div class="stats-grid">${topStats.map(([label, value, icon, foot]) => `<div class="stat-card"><div class="stat-heading">${escapeHtml(label)}<span class="stat-icon">${icon}</span></div><div class="stat-value">${escapeHtml(value)}</div><div class="stat-foot">${escapeHtml(foot)}</div></div>`).join("")}</div>
    <div class="dashboard-grid">
      <section class="panel"><div class="panel-heading"><div><h3>Portfolio growth</h3><p>Patent additions over the last 12 months</p></div></div>${growthChart(data.growth)}</section>
      <section class="panel"><div class="panel-heading"><div><h3>Portfolio by status</h3><p>Current filing overview</p></div><button class="text-button" data-page="Reports">Details →</button></div>${statusLegend(data.byStatus)}</section>
    </div>${patentTable(rows, { heading: "Recent patent activity" })}`;
}

function addButton(resource, label) {
  return resource && label && ["owner", "editor"].includes(state.user.role)
    ? `<button class="action-button strong" data-action="add-record" data-resource="${resource}">＋ ${escapeHtml(label)}</button>`
    : "";
}

function sectionHeader(page, label) {
  const title = page === "Inventory" ? "Patent portfolio" : page;
  return `<div class="page-title-row"><div><h1>${escapeHtml(title)}</h1><p>${escapeHtml(pageDescriptions[page])}</p></div>${addButton(({ Inventory: "patents", Products: "products", Suppliers: "suppliers", Management: "team", Showroom: "collections" })[page] || "", label)}</div>`;
}

function productMarkup(products) {
  const rows = products.map((product) => `<tr><td><div class="patent-name">${escapeHtml(product.name)}</div><div class="patent-id">${escapeHtml(product.description || "")}</div></td>
    <td>${escapeHtml(product.sku || "—")}</td><td>${escapeHtml(product.category || "—")}</td><td>${formatMoney(product.price)}</td>
    <td>${product.stockQuantity}</td><td>${product.patentIds.length}</td><td>${actionButtons("products", product)}</td></tr>`).join("");
  return `<div class="table-panel"><div class="table-heading"><h3>Products</h3><span class="subtle">${products.length} record${products.length === 1 ? "" : "s"}</span></div>
    <div class="table-scroll"><table><thead><tr><th>Product</th><th>SKU / barcode</th><th>Category</th><th>Price</th><th>In stock</th><th>Linked patents</th><th>Actions</th></tr></thead><tbody>${products.length ? rows : emptyRow(7, "No products yet. Add products with a price and opening stock to start selling.")}</tbody></table></div></div>`;
}

function posProductsMarkup() {
  const categories = ["All items", ...new Set(state.products.map((product) => product.category).filter(Boolean))];
  const query = state.posSearch.toLocaleLowerCase();
  const products = state.products.filter((product) => {
    const matchesCategory = state.posCategory === "All items" || product.category === state.posCategory;
    const matchesQuery = !query || [product.name, product.sku, product.category].some((value) => value.toLocaleLowerCase().includes(query));
    return matchesCategory && matchesQuery;
  });
  const canSell = ["owner", "editor"].includes(state.user.role);
  const categoryButtons = categories.map((category) => `<button class="pos-category${state.posCategory === category ? " active" : ""}" data-action="pos-category" data-category="${escapeHtml(category)}">${escapeHtml(category)}</button>`).join("");
  const cards = products.map((product) => {
    const inCart = state.cart.get(product.id)?.quantity || 0;
    const available = product.stockQuantity - inCart;
    const outOfStock = available <= 0;
    return `<button class="pos-product" data-action="pos-add" data-id="${escapeHtml(product.id)}" ${!canSell || outOfStock ? "disabled" : ""} aria-label="Add ${escapeHtml(product.name)} to cart">
      <span class="pos-product-art" aria-hidden="true">${escapeHtml((product.name || "?").trim().charAt(0).toUpperCase())}</span>
      <span class="pos-product-name">${escapeHtml(product.name)}</span>
      <span class="pos-product-meta">${escapeHtml(product.sku || product.category || "Product")}</span>
      <span class="pos-product-bottom"><span class="pos-product-price">${escapeHtml(formatMoney(product.price))}</span>
        <span class="pos-stock${available <= 5 ? " low" : ""}">${outOfStock ? "Out of stock" : `${available} left`}</span></span>
    </button>`;
  }).join("");
  return `<div class="pos-categories">${categoryButtons}</div><div class="pos-product-grid">${cards || `<div class="empty-note" style="grid-column:1/-1">${state.products.length ? "No products match this search." : "Your catalog is empty. Add a priced product with stock in Products to start selling."}</div>`}</div>`;
}

function cartTotals() {
  const subtotalCents = [...state.cart.values()].reduce(
    (total, item) => total + Math.round(item.product.price * 100) * item.quantity,
    0,
  );
  const taxRate = Number(state.settings?.taxRate || 0);
  const taxCents = Math.round(subtotalCents * taxRate / 100);
  return { subtotalCents, taxCents, totalCents: subtotalCents + taxCents };
}

function renderPosCart() {
  const target = document.getElementById("posCart");
  if (!target) {
    return;
  }
  const items = [...state.cart.values()];
  const quantity = items.reduce((total, item) => total + item.quantity, 0);
  const hasStockConflict = items.some(({ product, quantity: count }) => count > product.stockQuantity);
  const totals = cartTotals();
  const cashReceivedCents = Math.round(Number(state.amountReceived || 0) * 100);
  const changeCents = state.paymentMethod === "cash" ? Math.max(0, cashReceivedCents - totals.totalCents) : 0;
  const cashDifference = cashReceivedCents - totals.totalCents;
  const cartLines = items.length ? items.map(({ product, quantity: count }) => `<div class="pos-line">
      <div><div class="pos-line-name">${escapeHtml(product.name)}</div><div class="pos-line-price">${escapeHtml(formatMoney(product.price))} each</div>
        ${count > product.stockQuantity ? `<div class="pos-stock low">Only ${product.stockQuantity} left; adjust quantity to continue.</div>` : ""}
        <div class="pos-quantity"><button data-action="pos-quantity" data-id="${escapeHtml(product.id)}" data-delta="-1" aria-label="Decrease quantity">−</button>
          <span>${count}</span><button data-action="pos-quantity" data-id="${escapeHtml(product.id)}" data-delta="1" aria-label="Increase quantity">+</button>
          <button class="pos-remove" data-action="pos-remove" data-id="${escapeHtml(product.id)}" aria-label="Remove item">×</button></div></div>
      <div class="pos-line-total">${escapeHtml(formatMoneyCents(Math.round(product.price * 100) * count))}</div>
    </div>`).join("") : `<div class="pos-cart-empty">Your cart is waiting.<br>Add products to start a sale.</div>`;
  const receivedField = state.paymentMethod === "cash" ? `<label>Cash received<input id="posCashReceived" type="number" min="0" step="0.01" value="${escapeHtml(state.amountReceived)}" placeholder="0.00"></label>` : "";
  const canSell = ["owner", "editor"].includes(state.user.role);
  target.innerHTML = `<div class="pos-cart-head"><h2>Current sale</h2><span class="pos-cart-count">${quantity} item${quantity === 1 ? "" : "s"}</span>${items.length ? '<button class="pos-clear" data-action="pos-clear">Clear</button>' : ""}</div>
    <div class="pos-cart-lines">${cartLines}</div>
    <div class="pos-checkout">
      <div class="pos-payment">
        <label>Customer (optional)<input id="posCustomer" maxlength="120" value="${escapeHtml(state.customerName)}" placeholder="Walk-in customer"></label>
        <label>Payment method<select id="posPaymentMethod"><option value="cash" ${state.paymentMethod === "cash" ? "selected" : ""}>Cash</option><option value="card" ${state.paymentMethod === "card" ? "selected" : ""}>Card · record only</option><option value="other" ${state.paymentMethod === "other" ? "selected" : ""}>Other</option></select></label>
        ${receivedField}
      </div>
      <div class="pos-summary"><div class="pos-summary-row"><span>Subtotal</span><span>${escapeHtml(formatMoneyCents(totals.subtotalCents))}</span></div>
        <div class="pos-summary-row"><span>Tax (${escapeHtml(state.settings?.taxRate || 0)}%)</span><span>${escapeHtml(formatMoneyCents(totals.taxCents))}</span></div>
        <div class="pos-summary-row total"><span>Total due</span><span>${escapeHtml(formatMoneyCents(totals.totalCents))}</span></div>
        ${state.paymentMethod === "cash" && state.amountReceived ? `<div class="pos-summary-row pos-change"><span>${cashDifference >= 0 ? "Change due" : "Amount remaining"}</span><span>${escapeHtml(formatMoneyCents(cashDifference >= 0 ? changeCents : -cashDifference))}</span></div>` : ""}
      </div>
      ${canSell ? `<button class="pos-complete" data-action="pos-checkout" ${!items.length || hasStockConflict || (state.paymentMethod === "cash" && cashReceivedCents < totals.totalCents) ? "disabled" : ""}>Complete sale · ${escapeHtml(formatMoneyCents(totals.totalCents))}</button>` : `<p class="subtle">Your role can view the register but cannot complete sales.</p>`}
    </div>`;
}

function refreshPosTotals() {
  const summary = document.querySelector("#posCart .pos-summary");
  if (!summary) {
    return;
  }
  const totals = cartTotals();
  const receivedCents = Math.round(Number(state.amountReceived || 0) * 100);
  const difference = receivedCents - totals.totalCents;
  summary.innerHTML = `<div class="pos-summary-row"><span>Subtotal</span><span>${escapeHtml(formatMoneyCents(totals.subtotalCents))}</span></div>
    <div class="pos-summary-row"><span>Tax (${escapeHtml(state.settings?.taxRate || 0)}%)</span><span>${escapeHtml(formatMoneyCents(totals.taxCents))}</span></div>
    <div class="pos-summary-row total"><span>Total due</span><span>${escapeHtml(formatMoneyCents(totals.totalCents))}</span></div>
    ${state.paymentMethod === "cash" && state.amountReceived ? `<div class="pos-summary-row pos-change"><span>${difference >= 0 ? "Change due" : "Amount remaining"}</span><span>${escapeHtml(formatMoneyCents(Math.abs(difference)))}</span></div>` : ""}`;
  const checkout = document.querySelector("#posCart [data-action=\"pos-checkout\"]");
  if (checkout) {
    checkout.disabled = !state.cart.size
      || [...state.cart.values()].some(({ product, quantity }) => quantity > product.stockQuantity)
      || (state.paymentMethod === "cash" && receivedCents < totals.totalCents);
  }
}

function addPosProduct(id) {
  if (!["owner", "editor"].includes(state.user?.role)) {
    return;
  }
  const product = state.products.find((item) => item.id === id);
  if (!product) {
    showToast("This product is no longer available.");
    return;
  }
  const current = state.cart.get(id)?.quantity || 0;
  if (current >= product.stockQuantity) {
    showToast(`${product.name} is out of stock.`);
    return;
  }
  state.cart.set(id, { product, quantity: current + 1 });
  renderPosProductsIntoPage();
  renderPosCart();
}

function changePosQuantity(id, delta) {
  const item = state.cart.get(id);
  if (!item) {
    return;
  }
  const quantity = item.quantity + delta;
  if (quantity <= 0) {
    state.cart.delete(id);
  } else if (quantity <= item.product.stockQuantity) {
    state.cart.set(id, { ...item, quantity });
  } else {
    showToast("The cart quantity cannot exceed available stock.");
    return;
  }
  renderPosProductsIntoPage();
  renderPosCart();
}

function posMarkup() {
  return `<div class="pos-header"><div><h1>Point of sale</h1><p>${escapeHtml(pageDescriptions.POS)}</p></div><div class="pos-status">Register ready</div></div>
    <div class="pos-shell"><section class="pos-catalog">
      <form class="pos-tools" id="posSearchForm"><label class="pos-search"><input id="posSearch" value="${escapeHtml(state.posSearch)}" placeholder="Search name or scan barcode…" aria-label="Search or scan products"></label><button class="hidden" type="submit">Search</button></form>
      <div id="posProductArea">${posProductsMarkup()}</div>
    </section><section class="pos-cart" id="posCart"></section></div>`;
}

function salesMarkup() {
  const rows = state.sales.map((sale) => `<tr><td><div class="patent-name">${escapeHtml(sale.receiptNumber)}</div><div class="patent-id">${escapeHtml(formatDate(sale.createdAt))}</div></td>
    <td>${sale.items.reduce((total, item) => total + item.quantity, 0)} items</td><td>${escapeHtml(sale.customerName || "Walk-in")}</td>
    <td>${escapeHtml(capitalizeStatus(sale.paymentMethod))}</td><td><span class="status ${sale.status === "refunded" ? "inactive" : "active"}">${escapeHtml(capitalizeStatus(sale.status))}</span></td>
    <td><strong>${escapeHtml(formatMoneyCents(sale.totalCents))}</strong></td>
    <td><div class="row-actions"><button class="action-button" data-action="show-receipt" data-id="${escapeHtml(sale.id)}">Receipt</button>
      ${sale.status === "completed" && ["owner", "editor"].includes(state.user.role) ? `<button class="action-button" data-action="refund-sale" data-id="${escapeHtml(sale.id)}">Refund</button>` : ""}</div></td></tr>`).join("");
  return `<div class="page-title-row"><div><h1>Sales</h1><p>${escapeHtml(pageDescriptions.Sales)}</p></div><a class="action-button action-link" href="#" data-action="export-sales">↓ Export sales</a></div>
    <div class="sales-summary"><div class="stat-card"><div class="stat-heading">Sales today<span class="stat-icon">▤</span></div><div class="stat-value">${state.salesSummary.todayCount}</div><div class="stat-foot">Completed transactions</div></div>
      <div class="stat-card"><div class="stat-heading">Revenue today<span class="stat-icon">↗</span></div><div class="stat-value">${escapeHtml(formatMoneyCents(state.salesSummary.todayRevenueCents))}</div><div class="stat-foot">Recorded sales total</div></div>
      <div class="stat-card"><div class="stat-heading">Low-stock products<span class="stat-icon">!</span></div><div class="stat-value">${state.salesSummary.lowStockCount}</div><div class="stat-foot">Five units or fewer</div></div></div>
    <div class="table-panel sales-table"><div class="table-heading"><h3>Recent transactions</h3><span class="subtle">Latest ${state.sales.length} sales</span></div>
      <div class="table-scroll"><table><thead><tr><th>Receipt</th><th>Items</th><th>Customer</th><th>Payment</th><th>Status</th><th>Total</th><th></th></tr></thead>
      <tbody>${rows || emptyRow(7, "No sales yet. Completed checkouts will appear here.")}</tbody></table></div></div>`;
}

function showReceipt(sale) {
  const itemRows = sale.items.map((item) => `<tr>  <td>${escapeHtml(item.name)}<br><small>${item.sku ? `SKU ${escapeHtml(item.sku)} · ` : ""}${item.quantity} × ${escapeHtml(formatMoneyCents(item.unitPriceCents))}</small></td>
    <td style="text-align:right">${escapeHtml(formatMoneyCents(item.lineTotalCents))}</td></tr>`).join("");
  const receipt = `<h1>${escapeHtml(state.settings?.workspaceName || "ANUCHO")}</h1><p>${sale.status === "refunded" ? "REFUND RECORDED" : "Thank you for your purchase"}</p>
    <p>Receipt ${escapeHtml(sale.receiptNumber)}<br>${escapeHtml(new Date(sale.createdAt).toLocaleString())}</p>
    ${sale.customerName ? `<p>Customer: ${escapeHtml(sale.customerName)}</p>` : ""}
    <table><tbody>${itemRows}</tbody></table>
    <p>Subtotal: ${escapeHtml(formatMoneyCents(sale.subtotalCents))}<br>Tax: ${escapeHtml(formatMoneyCents(sale.taxCents))}</p>
    <p class="receipt-total">Total: ${escapeHtml(formatMoneyCents(sale.totalCents))}<br>Paid by ${escapeHtml(capitalizeStatus(sale.paymentMethod))}<br>Status: ${escapeHtml(capitalizeStatus(sale.status))}</p>
    ${sale.status === "refunded" ? `<p>Refunded ${escapeHtml(new Date(sale.refundedAt).toLocaleString())}<br>Reason: ${escapeHtml(sale.refundReason)}</p>` : ""}
    ${sale.paymentMethod === "cash" ? `<p>Cash received: ${escapeHtml(formatMoneyCents(sale.amountReceivedCents))}<br>Change: ${escapeHtml(formatMoneyCents(sale.changeCents))}</p>` : ""}`;
  document.getElementById("printReceipt").innerHTML = receipt;
  document.getElementById("dialogTitle").textContent = "Sale complete";
  dialogFields.innerHTML = `<div class="receipt-preview">${receipt}</div>`;
  dialogSubmit.textContent = "Print receipt";
  dialogSubmit.classList.remove("hidden");
  dialogForm.querySelectorAll('[data-action="close-dialog"]').forEach((button) => button.classList.remove("hidden"));
  dialogForm.onsubmit = (event) => {
    event.preventDefault();
    window.print();
    recordDialog.close();
  };
  recordDialog.showModal();
}

function showReceiptRefreshWarning(message) {
  const warning = document.createElement("p");
  warning.className = "auth-error";
  warning.setAttribute("role", "alert");
  warning.textContent = message;
  dialogFields.append(warning);
}

function refundSale(id) {
  const sale = state.sales.find((item) => item.id === id);
  if (!sale || sale.status !== "completed") {
    showToast("This sale is no longer available to refund.");
    return;
  }
  openForm(`Refund ${sale.receiptNumber}`, [
    { name: "reason", label: "Reason for refund", required: true, maxlength: 240, placeholder: "Customer return, duplicate sale…" },
  ], async (values) => {
    const result = await api(`/api/sales/${encodeURIComponent(id)}/refund`, {
      method: "POST",
      body: { reason: values.reason },
    });
    state.sales = state.sales.map((item) => item.id === id ? result.sale : item);
    let refreshWarning = "";
    try {
      const history = await api("/api/sales");
      state.sales = history.sales;
      state.salesSummary = history.summary;
    } catch (error) {
      refreshWarning = `Refund recorded, but sales history could not refresh: ${error.message}`;
    }
    pageContent.innerHTML = renderSection("Sales");
    showToast(refreshWarning || `Refund recorded for ${result.sale.receiptNumber}. Restock was updated.`);
  }, { submitLabel: "Confirm refund" });
}

async function completeSale() {
  const items = [...state.cart.values()].map(({ product, quantity }) => ({ productId: product.id, quantity }));
  if (!items.length) {
    return;
  }
  if ([...state.cart.values()].some(({ product, quantity }) => quantity > product.stockQuantity)) {
    showToast("Stock changed while this sale was open. Adjust the cart before checkout.");
    return;
  }
  const result = await api("/api/sales", {
    method: "POST",
    body: {
      items,
      paymentMethod: state.paymentMethod,
      amountReceived: state.paymentMethod === "cash" ? state.amountReceived : undefined,
      customerName: state.customerName,
    },
  });
  const purchasedItems = [...state.cart.values()];
  state.cart.clear();
  state.amountReceived = "";
  state.customerName = "";
  state.products = state.products.map((product) => {
    const purchased = purchasedItems.find((item) => item.product.id === product.id);
    return purchased ? { ...product, stockQuantity: product.stockQuantity - purchased.quantity } : product;
  });
  state.sales = [result.sale, ...state.sales.filter((sale) => sale.id !== result.sale.id)].slice(0, 100);
  renderPosProductsIntoPage();
  renderPosCart();
  let refreshWarning = "";
  try {
    const [products, sales] = await Promise.all([api("/api/products"), api("/api/sales")]);
    state.products = products.products;
    state.sales = sales.sales;
    state.salesSummary = sales.summary;
    renderPosProductsIntoPage();
    renderPosCart();
  } catch (error) {
    refreshWarning = `Sale recorded, but register data could not refresh: ${error.message}. Refresh the register before the next sale.`;
  }
  showReceipt(result.sale);
  if (refreshWarning) {
    showReceiptRefreshWarning(refreshWarning);
  }
}

function renderPosProductsIntoPage() {
  const target = document.getElementById("posProductArea");
  if (target) {
    target.innerHTML = posProductsMarkup();
  }
}

function supplierMarkup(suppliers) {
  const rows = suppliers.map((supplier) => `<tr><td><div class="patent-name">${escapeHtml(supplier.name)}</div><div class="patent-id">${escapeHtml(supplier.email || supplier.phone || "")}</div></td>
    <td>${escapeHtml(supplier.service || "—")}</td><td><span class="status ${escapeHtml(supplier.status)}">${escapeHtml(capitalizeStatus(supplier.status))}</span></td>
    <td>${actionButtons("suppliers", supplier)}</td></tr>`).join("");
  return `<div class="table-panel"><div class="table-heading"><h3>Supplier directory</h3><span class="subtle">${suppliers.length} partner${suppliers.length === 1 ? "" : "s"}</span></div>
    <div class="table-scroll"><table><thead><tr><th>Supplier</th><th>Service</th><th>Status</th><th>Actions</th></tr></thead><tbody>${suppliers.length ? rows : emptyRow(4, "No suppliers yet. Add a patent agent or service provider.")}</tbody></table></div></div>`;
}

function collectionMarkup(collections) {
  if (!collections.length) {
    return `<section class="panel"><div class="empty-note">No showroom collections yet. Add a collection and choose which patents to present.</div></section>`;
  }
  return `<div class="section-cards">${collections.map((collection) => `<article class="quick-card">
    <span class="status ${collection.isPublic ? "public" : "private"}">${collection.isPublic ? "Public" : "Private"}</span>
    <h3 style="margin-top:13px">${escapeHtml(collection.name)}</h3>
    <p>${escapeHtml(collection.description || "No description yet.")}</p>
    <p style="margin-top:10px">${collection.patentIds.length} selected patent${collection.patentIds.length === 1 ? "" : "s"}</p>
    <div style="margin-top:12px">${actionButtons("collections", collection)}</div></article>`).join("")}</div>`;
}

function teamMarkup(members) {
  const rows = members.map((member) => `<tr><td><div class="patent-name">${escapeHtml(member.name)}</div><div class="patent-id">${escapeHtml(member.email || member.phone || "")}</div></td>
    <td><span class="status ${escapeHtml(member.role)}">${escapeHtml(roleLabel(member.role))}</span></td><td>${member.mustChangePassword ? "Password update required" : "Active"}</td>
    <td><div class="row-actions">${member.id !== state.user.id ? `<button data-action="reset-password" data-id="${escapeHtml(member.id)}">Reset password</button>` : ""}${member.role !== "owner" ? `<button class="delete" data-action="delete-member" data-id="${escapeHtml(member.id)}">Remove</button>` : ""}</div></td></tr>`).join("");
  return `<div class="table-panel"><div class="table-heading"><h3>Workspace team</h3><span class="subtle">${members.length} member${members.length === 1 ? "" : "s"}</span></div>
    <div class="table-scroll"><table><thead><tr><th>Name</th><th>Role</th><th>Account</th><th>Actions</th></tr></thead><tbody>${members.length ? rows : emptyRow(4, "Your workspace team is empty.")}</tbody></table></div></div>`;
}

function reportsMarkup(report) {
  const statusSummary = report.byStatus.length
    ? report.byStatus.map((item) => `<div class="legend-row">${escapeHtml(capitalizeStatus(item.status))}<b>${item.count}</b></div>`).join("")
    : `<div class="empty-note">Add patents to start your report.</div>`;
  return `<div class="sales-summary" style="margin-top:15px"><div class="stat-card"><div class="stat-heading">Sales today<span class="stat-icon">▤</span></div><div class="stat-value">${report.todaySalesCount || 0}</div><div class="stat-foot">Completed transactions</div></div>
      <div class="stat-card"><div class="stat-heading">Revenue today<span class="stat-icon">↗</span></div><div class="stat-value">${escapeHtml(formatMoneyCents(report.todayRevenueCents || 0))}</div><div class="stat-foot">Recorded sales total</div></div>
      <div class="stat-card"><div class="stat-heading">Low-stock products<span class="stat-icon">!</span></div><div class="stat-value">${report.lowStockCount || 0}</div><div class="stat-foot">Five units or fewer</div></div></div>
    <section class="panel"><div class="panel-heading"><div><h3>Portfolio summary</h3><p>A live count from your patent records.</p></div>
    <a class="action-button action-link" href="#" data-action="export-reports">↓ Export CSV</a></div>
    <div class="section-cards">
      <article class="quick-card"><span class="stat-icon">◇</span><h3>${report.totalPatents} patents</h3><p>Total records in your workspace</p></article>
      <article class="quick-card"><span class="stat-icon">↻</span><h3>${report.renewalsDue} renewals due</h3><p>During the next 90 days</p></article>
      <article class="quick-card"><span class="stat-icon">↗</span><h3>${escapeHtml(formatMoney(report.estimatedPortfolioValue))}</h3><p>Combined estimated portfolio value</p></article>
    </div>
    <div class="panel-heading" style="margin:22px 0 8px"><div><h3>Records by status</h3></div></div><div class="legend" style="max-width:320px">${statusSummary}</div>
  </section>`;
}

function settingsMarkup(settings) {
  const isOwner = state.user.role === "owner";
  const controls = isOwner ? `
    <form class="settings-form" id="settingsForm">
      <label class="field-label" for="workspaceName">Workspace name</label><input id="workspaceName" name="workspaceName" maxlength="120" value="${escapeHtml(settings.workspaceName || "ANUCHO")}" required>
      <label class="field-label" for="currency">Currency</label><input id="currency" name="currency" maxlength="3" minlength="3" value="${escapeHtml(settings.currency || "USD")}" required>
      <label class="field-label" for="taxRate">Sales tax (%)</label><input id="taxRate" name="taxRate" type="number" min="0" max="100" step="0.01" value="${escapeHtml(settings.taxRate ?? 0)}" required>
      <label class="field-label" for="timezone">Time zone</label><input id="timezone" name="timezone" maxlength="80" value="${escapeHtml(settings.timezone || "UTC")}" required>
      <button class="action-button strong" style="margin-top:17px" type="submit">Save settings</button>
    </form>` : `<p class="subtle">Contact the workspace owner to change workspace settings.</p>`;
  return `<section class="panel"><div class="panel-heading"><div><h3>Store preferences</h3><p>Currency, local time and the tax rate applied at checkout.</p></div></div>${controls}</section>
    <section class="panel" style="margin-top:15px"><div class="panel-heading"><div><h3>Account & sign-in</h3><p>${escapeHtml(state.user.email || state.user.phone)} · ${escapeHtml(roleLabel(state.user.role))}</p></div></div>
      <p class="subtle">Sign-in is managed by Supabase Auth. Change your password here at any time.</p>
      <button class="action-button strong" style="margin-top:14px" data-action="change-password">Change password</button>
    </section>`;
}

function renderSection(page) {
  const heading = sectionHeader(page, ({
    Inventory: "Add patent",
    Products: "Add product",
    Suppliers: "Add supplier",
    Management: "Add member",
    Showroom: "Add collection",
  })[page]);
  if (page === "POS") {
    return posMarkup();
  }
  if (page === "Sales") {
    return salesMarkup();
  }
  if (page === "Inventory") {
    const due = state.patents.filter((patent) => patent.renewalDate && patent.renewalDate >= new Date().toISOString().slice(0, 10)).length;
    return `${heading}<div class="stats-grid" style="margin-bottom:15px">
      <div class="stat-card"><div class="stat-heading">Patent records<span class="stat-icon">◇</span></div><div class="stat-value">${state.patents.length}</div><div class="stat-foot">Stored in your portfolio</div></div>
      <div class="stat-card"><div class="stat-heading">Renewal dates<span class="stat-icon">↻</span></div><div class="stat-value">${due}</div><div class="stat-foot">Future renewal dates recorded</div></div>
      <div class="stat-card"><div class="stat-heading">Products<span class="stat-icon">▤</span></div><div class="stat-value">${state.products.length}</div><div class="stat-foot">Linked product records</div></div>
    </div>${patentTable(state.patents, { heading: "Patent inventory", showActions: true })}`;
  }
  if (page === "Products") {
    return `${heading}<section style="margin-top:15px">${productMarkup(state.products)}</section>`;
  }
  if (page === "Suppliers") {
    return `${heading}<section style="margin-top:15px">${supplierMarkup(state.suppliers)}</section>`;
  }
  if (page === "Reports") {
    return `${sectionHeader(page, "")}<section style="margin-top:15px">${reportsMarkup(state.dashboard)}</section>`;
  }
  if (page === "Management") {
    if (state.user.role !== "owner") {
      return `${sectionHeader(page, "")}<section class="panel"><div class="empty-note">Only the workspace owner can manage team accounts.</div></section>`;
    }
    return `${heading}<p class="subtle" style="margin:-10px 0 16px">New members receive a one-time temporary password that they must change at first sign-in.</p>${teamMarkup(state.members)}`;
  }
  if (page === "Showroom") {
    return `${heading}<p class="subtle" style="margin:-10px 0 16px">Collections are private until you explicitly set them to public.</p>${collectionMarkup(state.collections)}`;
  }
  if (page === "Settings") {
    return `${sectionHeader(page, "")}<div class="section-cards" style="margin-bottom:15px">
      <article class="quick-card"><span class="stat-icon">♙</span><h3>${escapeHtml(state.user.name)}</h3><p>${escapeHtml(roleLabel(state.user.role))}</p></article>
      <article class="quick-card"><span class="stat-icon">⌑</span><h3>Cloud database</h3><p>Workspace records stored in Supabase Postgres</p></article>
      <article class="quick-card"><span class="stat-icon">◈</span><h3>Live workspace</h3><p>Changes sync across signed-in staff devices</p></article>
    </div>${settingsMarkup(state.settings)}`;
  }
  return `${sectionHeader(page, "")}<section class="panel"><div class="empty-note">This page is not available.</div></section>`;
}

function setCurrentUser(user) {
  displayUser(user);
  loginScreen.classList.add("hidden");
  appShell.classList.remove("hidden");
}

async function renderPage(page) {
  if (!pageDescriptions[page] || state.passwordChangeRequired) {
    return;
  }
  state.page = page;
  const requestId = ++state.pageRequest;
  document.getElementById("crumbPage").textContent = page === "Inventory" ? "Patent portfolio" : page;
  document.querySelector(".topbar .search").classList.toggle("hidden", page === "POS");
  document.querySelectorAll(".nav-item[data-page]").forEach((item) => item.classList.toggle("active", item.dataset.page === page));
  pageContent.innerHTML = `<section class="panel"><div class="empty-note">Loading your workspace…</div></section>`;
  try {
    if (page === "Overview") {
      const [dashboard, result] = await Promise.all([
        api("/api/overview"),
        api(`/api/patents?q=${encodeURIComponent(state.search)}`),
      ]);
      state.dashboard = dashboard;
      state.patents = result.patents;
    } else if (page === "Inventory") {
      const [patents, products] = await Promise.all([
        api(`/api/patents?q=${encodeURIComponent(state.search)}`),
        api("/api/products"),
      ]);
      state.patents = patents.patents;
      state.products = products.products;
    } else if (page === "Products") {
      const [products, patents] = await Promise.all([api("/api/products"), api("/api/patents")]);
      state.products = products.products;
      state.patents = patents.patents;
    } else if (page === "POS") {
      state.products = (await api("/api/products")).products;
      reconcileCartProducts();
    } else if (page === "Sales") {
      const result = await api("/api/sales");
      state.sales = result.sales;
      state.salesSummary = result.summary;
    } else if (page === "Suppliers") {
      state.suppliers = (await api("/api/suppliers")).suppliers;
    } else if (page === "Reports") {
      state.dashboard = await api("/api/reports");
    } else if (page === "Management" && state.user.role === "owner") {
      state.members = (await api("/api/team")).members;
    } else if (page === "Showroom") {
      state.collections = (await api("/api/collections")).collections;
      state.patents = (await api("/api/patents")).patents;
    } else if (page === "Settings") {
      const [settings, profile] = await Promise.all([api("/api/settings"), api("/api/me")]);
      state.settings = settings.settings;
      state.user = profile.user;
      state.currency = state.settings.currency || "USD";
      displayUser(state.user);
    }
    if (requestId === state.pageRequest) {
      pageContent.innerHTML = page === "Overview" ? dashboardMarkup() : renderSection(page);
      if (page === "POS") {
        renderPosCart();
      }
    }
  } catch (error) {
    if (requestId === state.pageRequest) {
      pageContent.innerHTML = `<section class="panel"><div class="empty-note">${escapeHtml(error.message)}</div></section>`;
    }
  }
}

function openForm(title, fields, onSubmit, options = {}) {
  document.getElementById("dialogTitle").textContent = title;
  dialogFields.innerHTML = fields.map((field) => {
    const id = `dialog-${field.name}`;
    if (field.type === "checkbox") {
      return `<label class="field-label" for="${id}"><input type="checkbox" id="${id}" name="${field.name}" ${field.value ? "checked" : ""} ${field.required ? "required" : ""}>${escapeHtml(field.label)}</label>`;
    }
    const label = `<label class="field-label" for="${id}">${escapeHtml(field.label)}</label>`;
    if (field.type === "textarea") {
      return `${label}<textarea id="${id}" name="${field.name}" maxlength="${field.maxlength || 5000}" ${field.required ? "required" : ""} placeholder="${escapeHtml(field.placeholder || "")}">${escapeHtml(field.value || "")}</textarea>`;
    }
    if (field.type === "select" || field.type === "multi") {
      const selected = Array.isArray(field.value) ? field.value : [];
      const chosen = field.type === "select" ? String(field.value ?? "") : "";
      const optionsHtml = (field.options || []).map((option) => {
        const [value, display] = Array.isArray(option) ? option : [option.id, option.label];
        const isSelected = field.type === "multi" ? selected.includes(value) : chosen === value;
        return `<option value="${escapeHtml(value)}" ${isSelected ? "selected" : ""}>${escapeHtml(display)}</option>`;
      }).join("");
      return `${label}<select id="${id}" name="${field.name}" ${field.type === "multi" ? "multiple size=\"4\"" : ""} ${field.required ? "required" : ""}>${field.type === "select" ? '<option value="">Choose…</option>' : ""}${optionsHtml}</select>`;
    }
    return `${label}<input id="${id}" name="${field.name}" type="${escapeHtml(field.type || "text")}" maxlength="${field.maxlength || 500}" value="${escapeHtml(field.value || "")}" placeholder="${escapeHtml(field.placeholder || "")}" ${field.min !== undefined ? `min="${field.min}"` : ""} ${field.step ? `step="${field.step}"` : ""} ${field.required ? "required" : ""}>`;
  }).join("");
  dialogSubmit.textContent = options.submitLabel || "Save changes";
  dialogSubmit.classList.remove("hidden");
  dialogForm.querySelectorAll('[data-action="close-dialog"]').forEach((button) => button.classList.toggle("hidden", Boolean(options.required)));
  dialogForm.onsubmit = async (event) => {
    event.preventDefault();
    const values = {};
    for (const field of fields) {
      const input = dialogForm.elements.namedItem(field.name);
      if (field.type === "checkbox") {
        values[field.name] = input.checked;
      } else if (field.type === "multi") {
        values[field.name] = Array.from(input.selectedOptions, (option) => option.value);
      } else {
        values[field.name] = input.value.trim();
      }
    }
    dialogSubmit.disabled = true;
    try {
      await onSubmit(values);
      recordDialog.close();
    } catch (error) {
      showToast(error.message);
    } finally {
      dialogSubmit.disabled = false;
    }
  };
  recordDialog.showModal();
  dialogForm.querySelector("input,select,textarea")?.focus();
}

function openTemporaryPassword(memberName, email, password) {
  document.getElementById("dialogTitle").textContent = "Share the temporary password";
  dialogFields.innerHTML = `<p class="subtle">${escapeHtml(memberName)} must change this password at their first sign-in. This password is shown only once.</p>
    <label class="field-label" for="temporaryPassword">Temporary password</label>
    <input class="temp-password" id="temporaryPassword" readonly value="${escapeHtml(password)}" aria-label="One-time temporary password">`;
  dialogSubmit.textContent = "Copy password";
  dialogSubmit.classList.remove("hidden");
  dialogForm.querySelectorAll('[data-action="close-dialog"]').forEach((button) => button.classList.remove("hidden"));
  dialogForm.onsubmit = async (event) => {
    event.preventDefault();
    try {
      await navigator.clipboard.writeText(password);
      dialogSubmit.textContent = "Copied";
    } catch {
      document.getElementById("temporaryPassword").select();
      showToast("Select and copy the temporary password to share it securely.");
    }
  };
  recordDialog.showModal();
}

function recordFields(resource, record = {}) {
  if (resource === "patents") {
    return [
      { name: "title", label: "Patent title", value: record.title, required: true, maxlength: 200 },
      { name: "patentNumber", label: "Patent / application number", value: record.patentNumber, maxlength: 80 },
      { name: "owner", label: "Owner", value: record.owner, maxlength: 160 },
      { name: "category", label: "Category", value: record.category, maxlength: 100 },
      { name: "status", label: "Status", type: "select", value: record.status || "pending", options: patentStatuses, required: true },
      { name: "filingDate", label: "Filing date", type: "date", value: record.filingDate },
      { name: "renewalDate", label: "Renewal date", type: "date", value: record.renewalDate },
      { name: "estimatedValue", label: "Estimated value", type: "number", value: record.estimatedValue || "", min: "0", step: "any" },
      { name: "description", label: "Description", type: "textarea", value: record.description, maxlength: 5000 },
    ];
  }
  if (resource === "products") {
    return [
      { name: "name", label: "Product name", value: record.name, required: true, maxlength: 200 },
      { name: "sku", label: "SKU or barcode", value: record.sku, maxlength: 64 },
      { name: "category", label: "Category", value: record.category, maxlength: 100 },
      { name: "price", label: "Price", type: "number", value: record.price ?? "", min: "0", step: "0.01", required: true },
      { name: "stockQuantity", label: "Opening stock / quantity", type: "number", value: record.stockQuantity ?? 0, min: "0", step: "1", required: true },
      { name: "patentIds", label: "Linked patents (select all that apply)", type: "multi", value: record.patentIds || [], options: state.patents.map((patent) => [patent.id, `${patent.patentNumber || patent.id.slice(0, 8)} · ${patent.title}`]) },
      { name: "description", label: "Description", type: "textarea", value: record.description },
    ];
  }
  if (resource === "suppliers") {
    return [
      { name: "name", label: "Supplier or partner name", value: record.name, required: true, maxlength: 200 },
      { name: "service", label: "Service", value: record.service, maxlength: 120 },
      { name: "email", label: "Email address", type: "email", value: record.email, maxlength: 254 },
      { name: "phone", label: "Phone number (E.164 format)", type: "tel", value: record.phone, placeholder: "+14155550123", maxlength: 32 },
      { name: "status", label: "Status", type: "select", value: record.status || "active", options: supplierStatuses },
      { name: "notes", label: "Notes", type: "textarea", value: record.notes },
    ];
  }
  if (resource === "collections") {
    return [
      { name: "name", label: "Collection name", value: record.name, required: true, maxlength: 200 },
      { name: "description", label: "Description", type: "textarea", value: record.description },
      { name: "patentIds", label: "Choose patents", type: "multi", value: record.patentIds || [], options: state.patents.map((patent) => [patent.id, `${patent.patentNumber || patent.id.slice(0, 8)} · ${patent.title}`]) },
      { name: "isPublic", label: "Make this collection publicly viewable", type: "checkbox", value: record.isPublic || false },
    ];
  }
  return [];
}

function recordName(resource, record) {
  return record.title || record.name || resource;
}

async function addRecord(resource) {
  if (resource === "patents" || resource === "products" || resource === "suppliers" || resource === "collections") {
    openForm(`Add ${({ patents: "patent", products: "product", suppliers: "supplier", collections: "showroom collection" })[resource]}`, recordFields(resource), async (values) => {
      await api(`/api/${resource}`, { method: "POST", body: values });
      await renderPage(state.page);
      showToast("Record saved.");
    });
  } else if (resource === "team") {
    openForm("Add a team member", [
      { name: "name", label: "Full name", required: true, maxlength: 120 },
      { name: "identifier", label: "Email or international phone number", required: true, placeholder: "colleague@example.com" },
      { name: "role", label: "Workspace role", type: "select", value: "editor", options: [["editor", "Editor · add and update records"], ["reviewer", "Reviewer · read-only"]] },
    ], async (values) => {
      const result = await api("/api/team", { method: "POST", body: values });
      await renderPage("Management");
      setTimeout(() => openTemporaryPassword(result.member.name, result.member.email || result.member.phone, result.temporaryPassword), 0);
    }, { submitLabel: "Create member" });
  }
}

async function editRecord(resource, id) {
  const result = await api(`/api/${resource}/${encodeURIComponent(id)}`);
  const record = result[resource === "collections" ? "collection" : resource.slice(0, -1)];
  if (!record) {
    throw new Error("This record is no longer available.");
  }
  openForm(`Edit ${recordName(resource, record)}`, recordFields(resource, record), async (values) => {
    await api(`/api/${resource}/${encodeURIComponent(id)}`, { method: "PATCH", body: values });
    await renderPage(state.page);
    showToast("Changes saved.");
  });
}

async function deleteRecord(resource, id) {
  const result = await api(`/api/${resource}/${encodeURIComponent(id)}`);
  const record = result[resource === "collections" ? "collection" : resource.slice(0, -1)];
  if (!record || !window.confirm(`Remove "${recordName(resource, record)}" from your workspace?`)) {
    return;
  }
  await api(`/api/${resource}/${encodeURIComponent(id)}`, { method: "DELETE", body: {} });
  await renderPage(state.page);
  showToast("Record removed.");
}

async function changePassword(required = false) {
  openForm(required ? "Choose your new password" : "Change your password", [
    { name: "newPassword", label: "New password (at least 12 characters)", type: "password", required: true, maxlength: 1024 },
    { name: "confirmPassword", label: "Confirm new password", type: "password", required: true, maxlength: 1024 },
  ], async (values) => {
    if (values.newPassword.length < 12) {
      throw new Error("Choose a password with at least 12 characters.");
    }
    if (values.newPassword !== values.confirmPassword) {
      throw new Error("The password confirmation does not match.");
    }
    const result = await api("/api/auth/change-password", {
      method: "POST",
      body: { newPassword: values.newPassword },
    });
    state.user = result.user;
    state.passwordChangeRequired = false;
    document.querySelectorAll(".nav-item[data-page]").forEach((item) => { item.disabled = false; });
    displayUser(result.user);
    if (required) {
      await renderPage("POS");
    }
    showToast("Password updated.");
  }, { submitLabel: "Update password", required });
}

async function startWorkspace(user) {
  displayUser(user);
  setSetupMode(false);
  setCurrentUser(user);
  if (user.mustChangePassword) {
    showRequiredPasswordPage();
    changePassword(true);
    showToast("Choose a new password before using the workspace.");
    return;
  }
  await loadWorkspaceSettings();
  await renderPage("POS");
  connectLiveUpdates();
}

async function initializeApp() {
  if (!supabaseConfigured || !supabase) {
    showAuthError("This deployment is missing its Supabase URL or publishable key.");
    return;
  }
  try {
    const { setupComplete } = await api("/api/setup-status");
    setSetupMode(!setupComplete);
    const { data: sessionData, error: sessionError } = await supabase.auth.getSession();
    if (sessionError) throw sessionError;
    if (!sessionData.session) {
      return;
    }
    if (!setupComplete) {
      const ownerName = sessionData.session.user.user_metadata?.name
        || sessionData.session.user.email
        || sessionData.session.user.phone
        || "Workspace owner";
      await api("/api/setup", { method: "POST", body: { name: ownerName } });
    }
    const result = await api("/api/me");
    displayUser(result.user);
    setCurrentUser(result.user);
    if (result.user.mustChangePassword) {
      showRequiredPasswordPage();
      changePassword(true);
      return;
    }
    await loadWorkspaceSettings();
    await renderPage("POS");
    connectLiveUpdates();
  } catch (error) {
    if (error.message !== "Please sign in again.") {
      showAuthError(error.message);
    }
  }
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearAuthError();
  const submit = document.getElementById("authSubmit");
  submit.disabled = true;
  try {
    const identifier = document.getElementById("identity").value.trim();
    const password = document.getElementById("password").value;
    if (state.setup) {
      const name = document.getElementById("fullName").value.trim();
      const confirmation = document.getElementById("passwordConfirm").value;
      if (password !== confirmation) {
        throw new Error("The password confirmation does not match.");
      }
      if (password.length < 12) throw new Error("Use a password with at least 12 characters.");
      const signUpCredentials = state.mode === "phone"
        ? { phone: identifier.replace(/[\s().-]/g, ""), password, options: { data: { name } } }
        : { email: identifier.toLowerCase(), password, options: { data: { name } } };
      const { data, error } = await supabase.auth.signUp(signUpCredentials);
      if (error) throw error;
      document.getElementById("passwordConfirm").value = "";
      if (data.session) {
        const result = await api("/api/setup", { method: "POST", body: { name } });
        await startWorkspace(result.user);
      } else if (state.mode === "phone") {
        openForm("Verify your phone number", [
          { name: "code", label: "SMS verification code", required: true, maxlength: 12, autocomplete: "one-time-code" },
        ], async ({ code }) => {
          const verification = await supabase.auth.verifyOtp({ phone: identifier.replace(/[\s().-]/g, ""), token: code, type: "sms" });
          if (verification.error) throw verification.error;
          const result = await api("/api/setup", { method: "POST", body: { name } });
          await startWorkspace(result.user);
        }, { submitLabel: "Verify and create workspace" });
      } else {
        showAuthError("Check your email to confirm the account, then return here to finish workspace setup.");
      }
    } else {
      const credentials = state.mode === "phone"
        ? { phone: identifier.replace(/[\s().-]/g, ""), password }
        : { email: identifier.toLowerCase(), password };
      const { data, error } = await supabase.auth.signInWithPassword(credentials);
      if (error) throw error;
      document.getElementById("password").value = "";
      const { setupComplete } = await api("/api/setup-status");
      if (!setupComplete) {
        const name = data.user.user_metadata?.name || data.user.email || data.user.phone || "Workspace owner";
        const result = await api("/api/setup", { method: "POST", body: { name } });
        await startWorkspace(result.user);
      } else {
        const result = await api("/api/me");
        await startWorkspace(result.user);
      }
    }
  } catch (error) {
    showAuthError(error.message);
  } finally {
    submit.disabled = false;
  }
});

document.querySelectorAll(".auth-tab").forEach((tab) => tab.addEventListener("click", () => setAuthMode(tab.dataset.mode)));
document.getElementById("togglePassword").addEventListener("click", (event) => {
  const input = document.getElementById("password");
  input.type = input.type === "password" ? "text" : "password";
  event.currentTarget.textContent = input.type === "password" ? "Show" : "Hide";
});

document.getElementById("globalSearch").addEventListener("input", (event) => {
  state.search = event.target.value.trim();
  clearTimeout(state.searchTimer);
  if (state.page !== "Inventory") {
    if (state.search) {
      renderPage("Inventory");
    }
    return;
  }
  state.searchTimer = setTimeout(() => renderPage("Inventory"), 180);
});

document.addEventListener("input", (event) => {
  if (event.target.id === "posSearch") {
    state.posSearch = event.target.value.trim();
    renderPosProductsIntoPage();
  } else if (event.target.id === "posCashReceived") {
    state.amountReceived = event.target.value;
    refreshPosTotals();
  } else if (event.target.id === "posCustomer") {
    state.customerName = event.target.value;
  }
});

document.addEventListener("change", (event) => {
  if (event.target.id === "posPaymentMethod") {
    state.paymentMethod = event.target.value;
    renderPosCart();
  }
});

document.addEventListener("submit", (event) => {
  if (event.target.id === "posSearchForm") {
    event.preventDefault();
    const matches = state.products.filter((product) => {
      const query = state.posSearch.toLocaleLowerCase();
      return !query || [product.name, product.sku, product.category].some((value) => value.toLocaleLowerCase().includes(query));
    });
    if (matches.length === 1) {
      addPosProduct(matches[0].id);
    }
  }
});

document.getElementById("loginScreen").addEventListener("click", (event) => {
  const forgot = event.target.closest('[data-action="forgot"]');
  if (forgot) {
    showToast("Ask your workspace owner to reset your access in Management. Password reset email is not configured.");
  }
});

document.addEventListener("submit", async (event) => {
  if (event.target.id !== "settingsForm") {
    return;
  }
  event.preventDefault();
  const form = new FormData(event.target);
  const submit = event.target.querySelector('button[type="submit"]');
  submit.disabled = true;
  try {
    const result = await api("/api/settings", {
      method: "PATCH",
      body: {
        workspaceName: form.get("workspaceName"),
        currency: form.get("currency"),
        taxRate: Number(form.get("taxRate")),
        timezone: form.get("timezone"),
      },
    });
    state.settings = result.settings;
    state.currency = result.settings.currency || "USD";
    showToast("Workspace settings saved.");
  } catch (error) {
    showToast(error.message);
  } finally {
    submit.disabled = false;
  }
});

document.addEventListener("click", async (event) => {
  const pageButton = event.target.closest("[data-page]");
  if (pageButton) {
    state.search = "";
    document.getElementById("globalSearch").value = "";
    await renderPage(pageButton.dataset.page);
    return;
  }
  const button = event.target.closest("[data-action]");
  if (!button) {
    return;
  }
  try {
    if (button.dataset.action === "export-reports" || button.dataset.action === "export-sales") {
      event.preventDefault();
      await downloadCsv(button.dataset.action === "export-sales" ? "/api/sales.csv" : "/api/reports.csv");
    } else if (button.dataset.action === "pos-add") {
      addPosProduct(button.dataset.id);
    } else if (button.dataset.action === "pos-category") {
      state.posCategory = button.dataset.category;
      renderPosProductsIntoPage();
    } else if (button.dataset.action === "pos-quantity") {
      changePosQuantity(button.dataset.id, Number(button.dataset.delta));
    } else if (button.dataset.action === "pos-remove") {
      state.cart.delete(button.dataset.id);
      renderPosProductsIntoPage();
      renderPosCart();
    } else if (button.dataset.action === "pos-clear") {
      state.cart.clear();
      renderPosProductsIntoPage();
      renderPosCart();
    } else if (button.dataset.action === "pos-checkout") {
      await completeSale();
    } else if (button.dataset.action === "show-receipt") {
      const sale = state.sales.find((item) => item.id === button.dataset.id);
      if (sale) {
        showReceipt(sale);
      }
    } else if (button.dataset.action === "refund-sale") {
      refundSale(button.dataset.id);
    } else if (button.dataset.action === "print-receipt") {
      window.print();
    } else if (button.dataset.action === "add-record") {
      const resource = button.dataset.resource || (state.page === "Management" ? "team" : "");
      await addRecord(resource);
    } else if (button.dataset.action === "edit-record") {
      await editRecord(button.dataset.resource, button.dataset.id);
    } else if (button.dataset.action === "delete-record") {
      await deleteRecord(button.dataset.resource, button.dataset.id);
    } else if (button.dataset.action === "close-dialog") {
      recordDialog.close();
    } else if (button.dataset.action === "change-password") {
      changePassword(state.passwordChangeRequired);
    } else if (button.dataset.action === "notifications") {
      showToast("You’re all caught up.");
    } else if (button.dataset.action === "logout") {
      const { error } = await supabase.auth.signOut();
      if (error) throw error;
      showLogin();
    } else if (button.dataset.action === "reset-password") {
      const response = await api(`/api/team/${encodeURIComponent(button.dataset.id)}/reset-password`, {
        method: "POST",
        body: {},
      });
      openTemporaryPassword(response.member.name, response.member.email || response.member.phone, response.temporaryPassword);
      await renderPage("Management");
    } else if (button.dataset.action === "delete-member") {
      if (window.confirm("Remove this member and revoke their access?")) {
        await api(`/api/team/${encodeURIComponent(button.dataset.id)}`, { method: "DELETE" });
        await renderPage("Management");
        showToast("Team member removed.");
      }
    }
  } catch (error) {
    showToast(error.message);
  }
});

initializeApp();
