import mongoose from "mongoose";
import dns from "dns";
import env from "./config/env.js";
import logger from "./utils/logger.js";

/**
 * `strictQuery` is the single most important setting here.
 *
 * With it off (the Mongoose 7+ default), a filter containing an undefined
 * value has that key silently dropped — so `find({ hotelId: undefined })`
 * executes as `find({})` and returns every tenant's documents. Turning it on
 * makes that a thrown error instead of a data leak.
 */
mongoose.set("strictQuery", true);

/**
 * `sanitizeFilter` is deliberately NOT enabled.
 *
 * It rewrites any filter value containing `$` keys into an `$eq` comparison,
 * which does stop operator injection — but it cannot tell a user-supplied
 * `{"$ne": null}` from a developer-written `{ _id: { $in: [...] } }`, so it
 * breaks every legitimate operator query in the codebase unless each one is
 * wrapped in `mongoose.trusted()`.
 *
 * Injection is handled where the untrusted data actually enters instead:
 * `express-mongo-sanitize` strips `$`-prefixed keys from request bodies and
 * query strings, and the Zod schemas coerce every field to its declared type
 * before it reaches a service. That stops the attack without disarming the
 * query layer.
 */

/** Resolvers to fall back to when the system one can't answer SRV queries. */
const FALLBACK_DNS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"];

/**
 * Makes sure a `mongodb+srv://` host can actually be resolved.
 *
 * An SRV connection string is not a plain hostname — the driver must perform a
 * DNS SRV lookup to discover the cluster's shards. Plenty of real environments
 * can't: a resolver pointed at 127.0.0.1 with nothing listening, a VPN that
 * only forwards A records, corporate DNS that blocks SRV, or a container with
 * no resolver configured. The failure surfaces as
 * `querySrv ECONNREFUSED _mongodb._tcp.<host>`, which reads like a database
 * problem but is entirely a name-resolution one.
 *
 * When the system resolver can't do it, we point Node at public resolvers and
 * try again rather than letting the process die on someone's network config.
 */
const ensureSrvResolvable = async (uri) => {
  if (!uri.startsWith("mongodb+srv://")) return;

  const host = uri.split("@").pop()?.split(/[/?]/)[0];
  if (!host) return;

  const srvRecord = `_mongodb._tcp.${host}`;

  try {
    await dns.promises.resolveSrv(srvRecord);
    return; // System resolver is fine — leave it alone.
  } catch (systemError) {
    logger.warn(
      { host, code: systemError.code, resolvers: dns.getServers() },
      "system DNS cannot resolve SRV records — trying public resolvers"
    );
  }

  const original = dns.getServers();
  // Set globally, not on a Resolver instance: the MongoDB driver uses the
  // process-wide resolver, so a scoped one would not help it.
  dns.setServers([...FALLBACK_DNS, ...original]);

  try {
    await dns.promises.resolveSrv(srvRecord);
    logger.info({ host }, "SRV resolved via public DNS");
  } catch (fallbackError) {
    dns.setServers(original);
    throw new Error(
      `Cannot resolve ${srvRecord}.\n\n` +
        `  This is a DNS problem, not a database problem. Your resolver is ` +
        `${original.join(", ")} and it refused the SRV lookup that a\n` +
        `  "mongodb+srv://" connection string requires.\n\n` +
        `  Fixes, easiest first:\n` +
        `    1. Point your machine at a public DNS server (1.1.1.1 or 8.8.8.8).\n` +
        `    2. Disconnect from any VPN or proxy that intercepts DNS.\n` +
        `    3. Use the non-SRV connection string from Atlas: in the "Connect"\n` +
        `       dialog choose driver version 3.4 or earlier. It starts\n` +
        `       "mongodb://" and lists the shard hosts directly, so no SRV\n` +
        `       lookup is needed.\n\n` +
        `  Original error: ${fallbackError.code ?? fallbackError.message}`
    );
  }
};

const connectDb = async (databaseUrl) => {
  try {
    await ensureSrvResolvable(databaseUrl);

    await mongoose.connect(databaseUrl, {
      dbName: env.DATABASE_NAME,
      serverSelectionTimeoutMS: 15_000,
      maxPoolSize: 20,
      minPoolSize: 2,
      retryWrites: true,
    });

    logger.info({ database: env.DATABASE_NAME }, "database connected");

    mongoose.connection.on("error", (err) => {
      logger.error({ err }, "database connection error");
    });
    mongoose.connection.on("disconnected", () => {
      logger.warn("database disconnected");
    });

    return mongoose.connection;
  } catch (err) {
    logger.fatal(`Could not connect to the database.\n\n${err.message}`);
    process.exit(1);
  }
};

/**
 * True when the deployment can run multi-document transactions.
 *
 * Transactions need a replica set or a sharded cluster. Atlas gives you one;
 * a local standalone `mongod` does not, and every transactional route would
 * otherwise fail at runtime with an opaque driver error. Callers use this to
 * degrade to non-transactional writes rather than break.
 */
export const supportsTransactions = () => {
  const description = mongoose.connection.client?.topology?.description;
  if (!description) return false;
  return ["ReplicaSetWithPrimary", "Sharded", "LoadBalanced"].includes(
    description.type
  );
};

export default connectDb;
