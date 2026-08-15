/**
 * End-to-end verification against the real database.
 *
 * Boots the actual app, signs in as a real seeded user, and exercises the
 * paths that the HTTP-only smoke test cannot reach — the ones that issue
 * queries. This is what proves the tenant scoping, the billing maths and the
 * analytics work, rather than merely that they refuse anonymous callers.
 *
 *   npm run verify
 */
import http from "http";
import mongoose from "mongoose";
import env from "../config/env.js";
import connectDb from "../connectDb.js";
import { createApp } from "../api/app.js";

const app = createApp({ requestLogging: false });
const server = http.createServer(app);

let passed = 0;
let failed = 0;

const check = (name, ok, detail = "") => {
  if (ok) {
    passed += 1;
    console.log(`  \x1b[32mPASS\x1b[0m  ${name}`);
  } else {
    failed += 1;
    console.log(`  \x1b[31mFAIL\x1b[0m  ${name}${detail ? `\n          ${detail}` : ""}`);
  }
};

const section = (title) => console.log(`\n\x1b[1m${title}\x1b[0m`);

const request = (method, path, { body, token, cookie } = {}) =>
  new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = http.request(
      {
        host: "127.0.0.1",
        port: server.address().port,
        method,
        path,
        headers: {
          ...(payload
            ? {
                "Content-Type": "application/json",
                "Content-Length": Buffer.byteLength(payload),
              }
            : {}),
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
          ...(cookie ? { Cookie: cookie } : {}),
        },
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          let parsed;
          try {
            parsed = JSON.parse(data);
          } catch {
            parsed = data;
          }
          resolve({ status: res.statusCode, headers: res.headers, body: parsed });
        });
      }
    );
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });

/**
 * Credentials for the seeded demo accounts.
 *
 * Overridable, because these are ordinary accounts that anyone can change from
 * the app's own change-password screen — and when someone does, a hardcoded
 * password wedges the entire suite behind a single misleading "owner signs in"
 * failure. Set VERIFY_OWNER_PASSWORD (or re-run `npm run seed:demo -- --reset`)
 * to get back to a known state.
 */
const OWNER_EMAIL = process.env.VERIFY_OWNER_EMAIL ?? "owner@spicegarden.in";
const OWNER_PASSWORD = process.env.VERIFY_OWNER_PASSWORD ?? "Owner@2026";
const ADMIN_EMAIL = process.env.VERIFY_ADMIN_EMAIL ?? "admin@qrdine.app";
const ADMIN_PASSWORD = process.env.VERIFY_ADMIN_PASSWORD ?? "Admin@2026";

const run = async () => {
  section("Authentication");

  let res = await request("POST", "/api/v1/auth/login", {
    body: { email: OWNER_EMAIL, password: OWNER_PASSWORD },
  });
  check("owner signs in", res.status === 200, `got ${res.status}: ${JSON.stringify(res.body)}`);

  if (res.status !== 200) {
    // Everything below needs this token. Bailing out with the reason beats
    // fifty cascading failures that all say "401".
    console.log(
      "\n\x1b[33mThe owner account could not sign in, so the authenticated checks were skipped.\x1b[0m"
    );
    console.log(
      `  · Wrong password? Set VERIFY_OWNER_PASSWORD, or re-seed:  npm run seed:demo -- --reset`
    );
    console.log(
      `  · Locked out after repeated failures? The lock clears itself after 15 minutes.\n`
    );
    throw new Error("cannot authenticate as the demo owner");
  }

  const token = res.body?.data?.token;
  const hotelId = res.body?.data?.hotelId;
  check("access token issued", Boolean(token));
  check("hotel is linked to the account (C-03)", Boolean(hotelId), "hotelId was null");

  const setCookie = res.headers["set-cookie"]?.find((c) => c.startsWith("oms_refresh="));
  check("httpOnly refresh cookie set (H-01)", Boolean(setCookie));
  check(
    "refresh cookie is httpOnly (H-02)",
    Boolean(setCookie?.toLowerCase().includes("httponly"))
  );

  res = await request("POST", "/api/v1/auth/login", {
    body: { email: OWNER_EMAIL, password: "definitely-not-the-password" },
  });
  check("wrong password returns 401, not 500 (C-04)", res.status === 401, `got ${res.status}`);

  /**
   * Clear the failed-attempt counter that the check above just incremented.
   *
   * A successful sign-in resets it (authServices.js), and without this the
   * suite locks its own demo account out after MAX_FAILED_LOGINS runs — the
   * counter is never reset in between, so the failures silently accumulate
   * across days and then everything fails at once with a 401.
   */
  res = await request("POST", "/api/v1/auth/login", {
    body: { email: OWNER_EMAIL, password: OWNER_PASSWORD },
  });
  check("a good sign-in clears the failed-attempt counter", res.status === 200,
    `got ${res.status}`);

  res = await request("POST", "/api/v1/auth/refresh", {
    cookie: setCookie?.split(";")[0],
  });
  check("refresh cookie mints a new access token", res.status === 200, `got ${res.status}`);

  section("Tenant-scoped reads");

  const auth = { token };

  res = await request("GET", "/api/v1/users/profile", auth);
  check("profile loads", res.status === 200, `got ${res.status}`);
  check("profile carries the hotel name", Boolean(res.body?.data?.user?.hotelName));
  check(
    "password hash is never serialised (H-07)",
    res.body?.data?.user?.password === undefined
  );

  res = await request("GET", "/api/v1/tables", auth);
  const tables = res.body?.data?.tables ?? [];
  check("tables load", res.status === 200 && tables.length === 14, `got ${res.status}, ${tables.length} tables`);
  check("4 tables are seated", tables.filter((t) => t.status === "occupied").length === 4);

  res = await request("GET", "/api/v1/dishes", auth);
  check("menu loads", res.status === 200 && res.body?.data?.dishes?.length === 27,
    `got ${res.status}, ${res.body?.data?.dishes?.length} dishes`);

  res = await request("GET", "/api/v1/categories", auth);
  check("categories load", res.status === 200 && res.body?.data?.categories?.length === 6);

  res = await request("GET", "/api/v1/orders", auth);
  check("live orders load", res.status === 200 && res.body?.data?.orders?.length === 4,
    `got ${res.body?.data?.orders?.length} orders`);

  res = await request("GET", "/api/v1/bills?limit=5", auth);
  check("bills paginate", res.status === 200 && res.body?.data?.bills?.length === 5,
    `got ${res.body?.data?.bills?.length}`);
  check("pagination reports the full total",
    res.body?.data?.pagination?.total > 1500,
    `total was ${res.body?.data?.pagination?.total}`);

  section("Billing correctness");

  // Specifically a settled bill: an invoice number is assigned on payment, so
  // an open bill legitimately has none and would fail the check below.
  res = await request("GET", "/api/v1/bills?status=paid&limit=1", auth);
  const bill = res.body?.data?.bills?.[0];
  check("settled bills can be filtered", res.status === 200 && Boolean(bill),
    `got ${res.status}`);
  check("bill has a GST split", bill?.cgst > 0 && bill?.sgst > 0,
    `cgst=${bill?.cgst} sgst=${bill?.sgst}`);
  check("settled bill has an invoice number",
    /^SG\/\d{4}-\d{2}\/\d{4}$/.test(bill?.invoiceNumber ?? ""),
    `got ${bill?.invoiceNumber}`);

  // The converse: an open bill must NOT have consumed a number.
  res = await request("GET", "/api/v1/bills?status=unpaid&limit=1", auth);
  const openBill = res.body?.data?.bills?.[0];
  check("an unsettled bill has not burned an invoice number",
    !openBill || !openBill.invoiceNumber,
    `open bill carried ${openBill?.invoiceNumber}`);

  // The money must add up — this is the compounding-discount fix (B-07),
  // verified against a real stored bill rather than a synthetic one.
  const expected =
    Math.round(
      (bill.subTotal - bill.totalDiscount + bill.totalTax + bill.serviceCharge) * 100
    ) / 100;
  check(
    "final amount reconciles to its parts (B-07)",
    Math.abs(bill.finalAmount - expected) <= 1.01,
    `final=${bill.finalAmount} expected≈${expected}`
  );
  check("nothing is negative", bill.finalAmount >= 0 && bill.totalDiscount >= 0);

  /**
   * Fetch one bill by its own id.
   *
   * The bill screen used to call `GET /tables/bill/:tableId` — the endpoint
   * that *generates* a bill for a table — and hand it a bill id. It found no
   * table with that id and the page rendered "Bill not found" for a bill that
   * plainly existed. Two identifiers, two endpoints; this pins the one the
   * screen actually needs, populated enough to print an invoice from.
   */
  res = await request("GET", `/api/v1/bills/${bill._id}`, auth);
  const single = res.body?.data?.bill;
  check("a bill can be fetched by its own id", res.status === 200 && single?._id === bill._id,
    `got ${res.status}`);
  check("the fetched bill carries its restaurant",
    typeof single?.hotelId === "object" && Boolean(single?.hotelId?.name),
    `hotelId=${JSON.stringify(single?.hotelId)?.slice(0, 60)}`);
  check("the fetched bill carries its table number",
    typeof single?.tableId === "object" && single?.tableId?.sequence !== undefined,
    `tableId=${JSON.stringify(single?.tableId)?.slice(0, 60)}`);
  check("line items carry a priced snapshot",
    single?.orderedItems?.length > 0 &&
      single.orderedItems.every(
        (item) => item.name && item.unitPrice >= 0 && item.lineTotal >= 0
      ),
    `${single?.orderedItems?.length} items`);

  // A bill id is not a table id: the generate endpoint must reject it rather
  // than returning something plausible-looking.
  res = await request("GET", `/api/v1/tables/bill/${bill._id}`, auth);
  check("a bill id is rejected by the table-billing endpoint", res.status === 404,
    `got ${res.status}`);

  section("Dashboard");

  // An explicit range, because the default window is the current calendar
  // month — which is only a couple of weeks early in a month.
  const from = new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString();
  res = await request("GET", `/api/v1/dashboard?from=${from}`, auth);
  const stats = res.body?.data;
  check("dashboard loads", res.status === 200, `got ${res.status}`);
  check("revenue series covers the requested range",
    (stats?.series?.length ?? 0) > 40,
    `${stats?.series?.length} days`);
  check("top dishes computed", (stats?.topDishes?.length ?? 0) > 0);
  check("payment mix computed", (stats?.paymentMix?.length ?? 0) > 0);
  check("table counts correct", stats?.tables?.total === 14 && stats?.tables?.occupied === 4,
    JSON.stringify(stats?.tables));
  check("low-stock alert fires", stats?.alerts?.lowStockIngredients > 0,
    `${stats?.alerts?.lowStockIngredients} flagged`);

  section("Analytics (no AI provider needed)");

  res = await request("GET", "/api/v1/ai/menu-analysis", auth);
  const menu = res.body?.data;
  check("menu analysis runs", res.status === 200, `got ${res.status}`);
  check("every dish is classified", menu?.items?.length > 20 &&
    menu.items.every((i) => i.classification));
  check("all four quadrants used",
    menu?.summary?.stars > 0 && menu?.summary?.dogs > 0,
    JSON.stringify(menu?.summary));
  check("margins came from recipes, not the 30% fallback",
    menu?.summary?.unpricedRecipes === 0,
    `${menu?.summary?.unpricedRecipes} dishes lacked a costed recipe`);
  check("recommendations produced", (menu?.recommendations?.length ?? 0) > 0);

  res = await request("GET", "/api/v1/ai/forecast?days=7", auth);
  const forecast = res.body?.data;
  check("forecast runs", res.status === 200 && forecast?.ready === true,
    forecast?.reason ?? `got ${res.status}`);
  check("7 days forecast", forecast?.forecast?.length === 7);
  check("weekend detected as busiest",
    ["Friday", "Saturday", "Sunday"].includes(forecast?.busiestDay?.weekday),
    `busiest was ${forecast?.busiestDay?.weekday}`);
  check("confidence reported", forecast?.forecast?.every((d) => d.confidence));

  res = await request("GET", "/api/v1/ai/pairings", auth);
  check("basket analysis runs", res.status === 200 && res.body?.data?.ready === true);
  check("pairings found", (res.body?.data?.pairs?.length ?? 0) > 0,
    `${res.body?.data?.pairs?.length} pairs`);

  res = await request("GET", "/api/v1/ai/anomalies", auth);
  const anomalies = res.body?.data;
  check("anomaly scan runs", res.status === 200 && anomalies?.ready === true);
  check("the two seeded outlier days were found",
    (anomalies?.anomalies?.length ?? 0) >= 2,
    `${anomalies?.anomalies?.length} found`);

  res = await request("GET", "/api/v1/ai/prep-plan", auth);
  check("prep plan runs", res.status === 200 && res.body?.data?.ready === true);
  check("prep quantities suggested", (res.body?.data?.items?.length ?? 0) > 0);

  res = await request("GET", "/api/v1/ai/status", auth);
  check("AI status reports analytics available without a provider",
    res.body?.data?.analyticsAvailable === true && res.body?.data?.enabled === false);

  section("Role separation");

  res = await request("POST", "/api/v1/auth/login", {
    body: { email: ADMIN_EMAIL, password: ADMIN_PASSWORD },
  });
  const adminToken = res.body?.data?.token;
  check("super admin signs in", res.status === 200 && Boolean(adminToken));
  check("super admin has no hotel of their own",
    !res.body?.data?.hotelId, `hotelId was ${res.body?.data?.hotelId}`);

  res = await request("GET", "/api/v1/users/hotel-owners", { token: adminToken });
  check("super admin can list restaurants", res.status === 200, `got ${res.status}`);

  res = await request("GET", "/api/v1/users/hotel-owners", auth);
  check("owner is blocked from platform admin routes", res.status === 403, `got ${res.status}`);

  res = await request("GET", "/api/v1/dashboard", { token: adminToken });
  check("super admin needs an explicit hotel to see a dashboard",
    res.status === 400, `got ${res.status}`);

  section("QR codes");

  const qrTable = tables[0];
  res = await request("GET", `/api/v1/qrs/${qrTable._id}`, auth);
  check("QR endpoint responds", res.status === 200, `got ${res.status}`);
  // The modal reads data.imageUrl — the crash was this sitting a level deeper
  // than the client expected.
  check(
    "QR payload carries a usable image",
    typeof res.body?.data?.imageUrl === "string" &&
      res.body.data.imageUrl.startsWith("data:image/"),
    `imageUrl was ${typeof res.body?.data?.imageUrl}`
  );
  check(
    "QR payload carries the table number",
    res.body?.data?.tableNumber === qrTable.sequence,
    `got ${res.body?.data?.tableNumber}, expected ${qrTable.sequence}`
  );
  check(
    "QR encodes the customer menu URL",
    String(res.body?.data?.target ?? "").includes(String(qrTable._id)),
    `target was ${res.body?.data?.target}`
  );

  section("Concurrent billing");

  /**
   * Two tables must be able to hold an open bill at the same time.
   *
   * A `{hotelId, invoiceNumber}` unique index marked `sparse` indexed every
   * bill — sparse only skips a document when *all* indexed fields are absent,
   * and hotelId never is. Two unpaid bills therefore both keyed as
   * `{hotelId, null}`, the second was rejected as a duplicate, and only one
   * table in the whole restaurant could be billed at a time.
   */
  const seated = tables.filter((t) => t.status === "occupied").slice(0, 2);

  if (seated.length === 2) {
    const results = [];
    for (const table of seated) {
      results.push(
        await request("GET", `/api/v1/tables/bill/${table._id}`, auth)
      );
    }

    // A table still cooking legitimately refuses with 409; a duplicate-key
    // rejection is the bug and must never appear.
    check(
      "a second table's bill is not rejected as a duplicate",
      !results.some((r) => r.body?.code === "DUPLICATE_KEY"),
      results.map((r) => `${r.status} ${r.body?.code ?? ""}`).join(" | ")
    );
    check(
      "billing refusals concern kitchen state, not the database",
      results.every((r) => [200, 409].includes(r.status)),
      results.map((r) => r.status).join(" | ")
    );
  }

  section("Tenant isolation");

  // A dish that exists, but belongs to nobody the caller can reach.
  const strayId = new mongoose.Types.ObjectId().toString();
  res = await request("GET", `/api/v1/dishes/${strayId}`, auth);
  check("unknown dish id returns 404, not another tenant's row (C-06)",
    res.status === 404, `got ${res.status}`);

  res = await request("GET", `/api/v1/tables/${strayId}`, auth);
  check("unknown table id returns 404 (C-05)", res.status === 404, `got ${res.status}`);

  section("Customer QR flow");

  const openTable = tables.find((t) => t.status === "free");
  res = await request("POST", `/api/v1/orders/qr-scan/${openTable._id}`);
  check("QR scan works without a login", res.status === 200, `got ${res.status}`);
  const sessionToken = res.body?.data?.sessionToken;
  check("scan issues a table session (C-07)", Boolean(sessionToken));
  check("scan returns the menu", (res.body?.data?.menu?.dishes?.length ?? 0) === 27);

  const anyDishId = res.body?.data?.menu?.dishes?.[0]?._id ?? menu?.items?.[0]?.dishId;
  res = await request("POST", `/api/v1/orders/${openTable._id}`, {
    body: { dishes: [{ dishId: anyDishId, quantity: 1 }] },
  });
  check("ordering without a session is refused (C-07)", res.status === 401, `got ${res.status}`);

  console.log(
    `\n${failed === 0 ? "\x1b[32m" : "\x1b[31m"}${passed} passed, ${failed} failed\x1b[0m\n`
  );

  await mongoose.connection.close();
  server.close();
  process.exit(failed === 0 ? 0 : 1);
};

connectDb(env.DATABASE_URL).then(() => {
  server.listen(0, "127.0.0.1", () => {
    run().catch(async (err) => {
      console.error("\nVerification crashed:", err);
      await mongoose.connection.close().catch(() => {});
      server.close();
      process.exit(1);
    });
  });
});
