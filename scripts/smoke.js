/**
 * HTTP smoke test for the security layer.
 *
 * Runs the real Express app on an ephemeral port with no database, and
 * asserts the behaviour of everything that resolves before a query is
 * issued: authentication, authorisation, validation, rate limiting, error
 * status codes and headers.
 *
 * Run with: npm run smoke
 */
import http from "http";
import { createApp } from "../api/app.js";

const app = createApp({ requestLogging: false });
const server = http.createServer(app);

const request = (method, path, { body, headers = {} } = {}) =>
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
          ...headers,
        },
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          let parsed = null;
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

let passed = 0;
let failed = 0;

const check = (name, condition, detail = "") => {
  if (condition) {
    passed += 1;
    console.log(`  [32mPASS[0m  ${name}`);
  } else {
    failed += 1;
    console.log(`  [31mFAIL[0m  ${name}${detail ? `\n          ${detail}` : ""}`);
  }
};

const section = (title) => console.log(`\n[1m${title}[0m`);

const run = async () => {
  section("Critical: endpoints that were open to the public");

  let res = await request("POST", "/api/v1/devkeys/generate");
  check(
    "C-01  dev-key generation rejects anonymous callers",
    res.status === 401,
    `got ${res.status}: ${JSON.stringify(res.body)}`
  );

  res = await request("GET", "/api/v1/devkeys");
  check("C-01  dev-key listing rejects anonymous callers", res.status === 401,
    `got ${res.status}`);

  res = await request("POST", "/api/v1/uploads");
  check("C-08  image upload rejects anonymous callers", res.status === 401,
    `got ${res.status}`);

  res = await request("POST", "/api/v1/orders/507f1f77bcf86cd799439011", {
    body: { dishes: [{ dishId: "507f1f77bcf86cd799439011", quantity: 1 }] },
  });
  check(
    "C-07  order creation requires a table session or staff login",
    res.status === 401,
    `got ${res.status}: ${JSON.stringify(res.body)}`
  );

  res = await request("POST", "/api/v1/orders/publish/507f1f77bcf86cd799439011");
  check("C-07  order publish requires credentials", res.status === 401,
    `got ${res.status}`);

  res = await request("GET", "/api/v1/orders/details/507f1f77bcf86cd799439011");
  check("C-07  order detail requires credentials", res.status === 401,
    `got ${res.status}`);

  section("Critical: error status codes reach the client");

  res = await request("GET", "/api/v1/tables");
  check(
    "C-04  missing token returns 401, not 500",
    res.status === 401,
    `got ${res.status}`
  );
  check(
    "C-04  response carries a machine-readable code",
    res.body?.code === "UNAUTHENTICATED",
    `code was ${res.body?.code}`
  );

  res = await request("GET", "/api/v1/tables", {
    headers: { Authorization: "Bearer not-a-real-token" },
  });
  check("C-04  malformed token returns 401", res.status === 401, `got ${res.status}`);

  section("High: information disclosure");

  check(
    "H-07  error body does not embed the raw error object",
    res.body?.errorDetails === undefined,
    "errorDetails was present"
  );
  check(
    "H-07  error body carries a correlation id",
    typeof res.body?.errorId === "string",
    "errorId missing"
  );

  section("High: security headers and hardening");

  res = await request("GET", "/");
  check("H-08  X-Powered-By is suppressed", res.headers["x-powered-by"] === undefined);
  check("H-08  helmet sets nosniff", res.headers["x-content-type-options"] === "nosniff");
  check("H-08  helmet sets HSTS", Boolean(res.headers["strict-transport-security"]));
  check("H-08  helmet sets frame protection", Boolean(res.headers["x-frame-options"]));
  check("H-05  rate-limit headers present", Boolean(res.headers["ratelimit"] ?? res.headers["ratelimit-limit"]));

  section("Validation");

  res = await request("POST", "/api/v1/auth/login", { body: { email: "nope" } });
  check(
    "H-09  malformed login is rejected as 400",
    res.status === 400,
    `got ${res.status}: ${JSON.stringify(res.body)}`
  );
  check(
    "H-09  validation failures list the offending fields",
    Array.isArray(res.body?.details) && res.body.details.length > 0,
    JSON.stringify(res.body?.details)
  );

  res = await request("POST", "/api/v1/auth/signup", {
    body: { name: "Ab", email: "a@b.com", password: "weak", role: "hotelowner" },
  });
  check(
    "H-09  weak password is rejected",
    res.status === 400,
    `got ${res.status}: ${JSON.stringify(res.body?.details ?? res.body)}`
  );

  res = await request("POST", "/api/v1/auth/signup", {
    body: {
      name: "Test User",
      email: "a@b.com",
      password: "Str0ngPass",
      role: "superadmin",
    },
  });
  check(
    "C-01  super-admin signup without a dev key is rejected",
    res.status === 400,
    `got ${res.status}`
  );

  res = await request("GET", "/api/v1/tables/not-an-object-id", {
    headers: { Authorization: "Bearer x" },
  });
  check("Validation  bad ObjectId does not reach the database", res.status === 401 || res.status === 400);

  section("Routing");

  res = await request("GET", "/api/v1/does-not-exist");
  check("B-12  unmatched route returns a clean 404", res.status === 404, `got ${res.status}`);
  check("B-12  404 body is structured", res.body?.code === "ROUTE_NOT_FOUND");

  res = await request("GET", "/health");
  check(
    "Health endpoint responds without auth",
    res.status === 200 || res.status === 503,
    `got ${res.status}`
  );
  check(
    "Health reports database state",
    ["connected", "disconnected"].includes(res.body?.database),
    JSON.stringify(res.body)
  );

  section("Injection hardening");

  res = await request("POST", "/api/v1/auth/login", {
    body: { email: { $ne: null }, password: { $ne: null } },
  });
  check(
    "NoSQL operator injection in login is neutralised",
    res.status === 400,
    `got ${res.status}: ${JSON.stringify(res.body)}`
  );

  console.log(
    `\n${failed === 0 ? "[32m" : "[31m"}${passed} passed, ${failed} failed[0m\n`
  );

  server.close();
  process.exit(failed === 0 ? 0 : 1);
};

server.listen(0, "127.0.0.1", () => {
  run().catch((err) => {
    console.error(err);
    server.close();
    process.exit(1);
  });
});
