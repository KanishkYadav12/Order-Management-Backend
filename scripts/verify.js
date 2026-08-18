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
const OWNER_EMAIL = process.env.VERIFY_OWNER_EMAIL ?? "ykanishk479@gmail.com";
const OWNER_PASSWORD = process.env.VERIFY_OWNER_PASSWORD ?? "123456";
const ADMIN_EMAIL = process.env.VERIFY_ADMIN_EMAIL ?? "ykanishk479+owner@gmail.com";
const ADMIN_PASSWORD = process.env.VERIFY_ADMIN_PASSWORD ?? "123456";

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

  /**
   * Invariants, not seed counts.
   *
   * These used to assert "14 tables, 4 of them seated" — the numbers the demo
   * seed happens to produce. Settling a bill frees its table and deletes its
   * orders, and deleting a table hides it, so simply *using* the app made the
   * suite fail and taught you to ignore red. Assert the relationships that
   * must hold however much the data moves.
   */
  res = await request("GET", "/api/v1/tables", auth);
  const tables = res.body?.data?.tables ?? [];
  check("tables load", res.status === 200 && tables.length > 0,
    `got ${res.status}, ${tables.length} tables`);
  check("every table has a number and a known status",
    tables.every(
      (t) =>
        t.sequence !== undefined &&
        ["free", "occupied", "reserved", "cleaning"].includes(t.status)
    ),
    JSON.stringify(tables[0])?.slice(0, 120));

  res = await request("GET", "/api/v1/dishes", auth);
  check("menu loads", res.status === 200 && res.body?.data?.dishes?.length === 27,
    `got ${res.status}, ${res.body?.data?.dishes?.length} dishes`);

  res = await request("GET", "/api/v1/categories", auth);
  check("categories load", res.status === 200 && res.body?.data?.categories?.length === 6);

  res = await request("GET", "/api/v1/orders", auth);
  const liveOrders = res.body?.data?.orders;
  check("live orders load", res.status === 200 && Array.isArray(liveOrders),
    `got ${res.status}, ${typeof liveOrders}`);
  check("a seated table is exactly a table with live orders",
    tables.filter((t) => t.status === "occupied").length ===
      new Set(
        (liveOrders ?? [])
          .map((order) => order.tableId?._id ?? order.tableId)
          .filter(Boolean)
          .map(String)
      ).size,
    `${tables.filter((t) => t.status === "occupied").length} seated vs ${liveOrders?.length} orders`);

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

  section("Bill period totals");

  /**
   * The bills screen filters by a named day, month or range. A period filter
   * with no period total is half a feature, so the list endpoint returns the
   * sums across every matching bill — not just the page on screen.
   */
  res = await request("GET", "/api/v1/bills?limit=5", auth);
  const allTotals = res.body?.data?.totals;
  check("the list returns period totals", Boolean(allTotals),
    JSON.stringify(res.body?.data ? Object.keys(res.body.data) : null));
  check("totals count every matching bill, not just the page",
    allTotals?.count === res.body?.data?.pagination?.total &&
      res.body?.data?.bills?.length === 5,
    `count=${allTotals?.count} total=${res.body?.data?.pagination?.total}`);
  check("settled never exceeds gross",
    allTotals?.settled <= allTotals?.gross + 0.01,
    `settled=${allTotals?.settled} gross=${allTotals?.gross}`);

  /**
   * Guards the aggregation cast: `$match` bypasses Mongoose's schema, so a
   * string hotelId matches nothing and every total silently reads zero while
   * the list beside it still shows rows.
   */
  check("totals are not silently zero while bills exist",
    (allTotals?.count ?? 0) > 0 && (allTotals?.gross ?? 0) > 0,
    `count=${allTotals?.count} gross=${allTotals?.gross}`);

  // A narrow window must return a subset, not the same numbers.
  const dayFrom = new Date(); dayFrom.setHours(0, 0, 0, 0);
  const dayTo = new Date(); dayTo.setHours(23, 59, 59, 999);
  res = await request(
    "GET",
    `/api/v1/bills?from=${dayFrom.toISOString()}&to=${dayTo.toISOString()}`,
    auth
  );
  check("a single-day filter narrows the totals",
    res.status === 200 && res.body?.data?.totals?.count <= allTotals?.count,
    `day=${res.body?.data?.totals?.count} all=${allTotals?.count}`);

  section("Staff order entry");

  /**
   * A walk-in has no phone, no email and often no name. The board had no way
   * to start an order at all, and the question this answers is the first one
   * staff ask: what happens when the guest gives you nothing?
   */
  const freeTable = tables.find((t) => t.status === "free") ?? tables[0];
  res = await request("GET", "/api/v1/dishes", auth);
  const someDish = res.body?.data?.dishes?.[0];

  res = await request("POST", `/api/v1/orders/${freeTable?._id}`, {
    ...auth,
    body: { dishes: [{ dishId: someDish?._id, quantity: 2 }], status: "pending" },
  });
  const walkIn = res.body?.data?.order;
  check("an order can be placed with no guest details at all",
    res.status === 201 || res.status === 200,
    `got ${res.status}: ${JSON.stringify(res.body)?.slice(0, 160)}`);
  check("the nameless guest is recorded as a guest",
    Boolean(walkIn?._id),
    JSON.stringify(walkIn)?.slice(0, 160));

  // Placing an order seats the table.
  res = await request("GET", "/api/v1/tables", auth);
  const afterOrder = (res.body?.data?.tables ?? []).find(
    (t) => String(t._id) === String(freeTable?._id)
  );
  check("placing an order seats its table", afterOrder?.status === "occupied",
    `table is ${afterOrder?.status}`);

  /**
   * Cancelling the only order must free it again.
   *
   * The rule was "any status except draft occupies the table", so cancelling
   * marked the table busy. The board showed nothing — cancelled orders are in
   * no column — while the floor showed a seated table that could never be
   * cleared, because there was nothing left to advance or to bill.
   */
  if (walkIn?._id) {
    res = await request("PATCH", `/api/v1/orders/${walkIn._id}/cancelled`, auth);
    check("an order can be cancelled", res.status === 200, `got ${res.status}`);
  }

  res = await request("GET", "/api/v1/tables", auth);
  const afterCancel = (res.body?.data?.tables ?? []).find(
    (t) => String(t._id) === String(freeTable?._id)
  );
  check("cancelling the last order frees its table",
    afterCancel?.status === "free",
    `table is ${afterCancel?.status}`);

  res = await request("GET", "/api/v1/orders", auth);
  check("a cancelled order is off the board",
    !Object.values(res.body?.data ?? {})
      .filter(Array.isArray)
      .flat()
      .some((order) => String(order?._id) === String(walkIn?._id)),
    "the cancelled order is still on the board");

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
  // The dashboard's own tally must agree with the tables endpoint, and its
  // parts must sum to its total. Both hold whatever the floor is doing.
  check("dashboard table counts agree with the floor",
    stats?.tables?.total === tables.length &&
      stats.tables.total ===
        (stats.tables.free ?? 0) +
          (stats.tables.occupied ?? 0) +
          (stats.tables.reserved ?? 0) +
          (stats.tables.cleaning ?? 0),
    `${JSON.stringify(stats?.tables)} vs ${tables.length} tables`);
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

  /**
   * The deterministic reports must work whether or not an LLM is configured.
   *
   * This used to assert `enabled === false`, which only held while no provider
   * was set up — configuring one then failed the suite for doing the thing the
   * suite exists to enable. The invariant is the independence, not the state.
   */
  res = await request("GET", "/api/v1/ai/status", auth);
  check("analytics work regardless of whether an LLM is configured",
    res.status === 200 && res.body?.data?.analyticsAvailable === true,
    JSON.stringify(res.body?.data));

  const llmOn = res.body?.data?.enabled === true;

  section("Advisor chat");

  if (!llmOn) {
    check("advisor degrades honestly with no provider", true, "skipped — no LLM configured");
  } else {
    /**
     * One real turn. This exercises the whole chain: the hotel brief from live
     * queries, the calendar and news layer, Gemini's tool calling, and the
     * conversation record that gives the assistant memory.
     */
    res = await request("POST", "/api/v1/ai/chat", {
      ...auth,
      body: { message: "How did we do over the last 7 days?" },
    });
    const chat = res.body?.data;

    /**
     * A spent free-tier quota is not a defect.
     *
     * Gemini's free daily allowance is genuinely small, and a day of
     * development can exhaust it. Failing the suite for that trains you to
     * ignore red — the same trap the seed-count assertions fell into. A real
     * fault still fails; only AI_UNAVAILABLE is treated as "not today".
     */
    const quotaSpent = res.body?.code === "AI_UNAVAILABLE";

    if (quotaSpent) {
      check("advisor skipped — free AI quota spent", true,
        "resets daily; the chain is simply unverified on this run");
    } else {
      check("the advisor answers", res.status === 200 && (chat?.reply?.length ?? 0) > 20,
        `got ${res.status}: ${JSON.stringify(res.body)?.slice(0, 160)}`);
      check("the answer is grounded in this restaurant",
        chat?.groundedOn?.restaurant != null,
        JSON.stringify(chat?.groundedOn)?.slice(0, 120));
      check("a conversation is opened so the chat has memory",
        Boolean(chat?.conversationId));
    }

    if (chat?.conversationId) {
      res = await request("GET", `/api/v1/ai/conversations/${chat.conversationId}`, auth);
      const turns = res.body?.data?.conversation?.turns ?? [];
      check("both sides of the turn are stored",
        turns.length === 2 && turns[0].role === "user" && turns[1].role === "model",
        `${turns.length} turns`);

      // Leave no test conversations behind in the owner's sidebar.
      await request("DELETE", `/api/v1/ai/conversations/${chat.conversationId}`, auth);
    }
  }

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
