/**
 * Creates the first super-admin account.
 *
 * This is the only way to bootstrap the platform now that the dev-key routes
 * require an existing super admin. Previously anyone could mint a dev key
 * over the public API and register themselves as one.
 *
 * Usage:
 *   node scripts/seedSuperAdmin.js --email you@example.com --name "Your Name"
 *
 * The password is read from the SEED_PASSWORD environment variable, so it
 * never lands in your shell history:
 *   SEED_PASSWORD='...' node scripts/seedSuperAdmin.js --email ... --name ...
 */
import mongoose from "mongoose";
import crypto from "crypto";
import env from "../config/env.js";
import connectDb from "../connectDb.js";
import { SuperAdmin, findUserByEmail } from "../models/userModel.js";
import { ROLES } from "../utils/constant.js";

const parseArgs = () => {
  const args = {};
  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i].startsWith("--")) {
      args[argv[i].slice(2)] = argv[i + 1];
      i += 1;
    }
  }
  return args;
};

const run = async () => {
  const { email, name } = parseArgs();

  if (!email || !name) {
    console.error(
      'Usage: node scripts/seedSuperAdmin.js --email you@example.com --name "Your Name"'
    );
    process.exit(1);
  }

  const password =
    process.env.SEED_PASSWORD ??
    // A generated password is printed once and must be changed at first login.
    `${crypto.randomBytes(6).toString("base64url")}Aa1`;

  await connectDb(env.DATABASE_URL);

  const existing = await findUserByEmail(email);
  if (existing) {
    console.error(`An account already exists for ${email}.`);
    await mongoose.connection.close();
    process.exit(1);
  }

  const admin = await SuperAdmin.create({
    name,
    email,
    password,
    role: ROLES.SUPER_ADMIN,
    isApproved: true,
    isVerified: true,
  });

  console.log("\nSuper admin created.\n");
  console.log(`  email     ${admin.email}`);
  if (!process.env.SEED_PASSWORD) {
    console.log(`  password  ${password}`);
    console.log("\n  Change this password the first time you sign in.\n");
  }

  await mongoose.connection.close();
  process.exit(0);
};

run().catch(async (err) => {
  console.error("Seed failed:", err.message);
  await mongoose.connection.close().catch(() => {});
  process.exit(1);
});
