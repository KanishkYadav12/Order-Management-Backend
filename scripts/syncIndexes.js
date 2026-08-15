/**
 * Brings the database's indexes in line with the schemas.
 *
 * Mongoose creates a missing index but will **not** alter one that already
 * exists with different options — it silently leaves the old definition in
 * place. So changing `sparse` to `partialFilterExpression`, or adding
 * `unique`, needs the stale index dropped first. `syncIndexes()` does exactly
 * that: drop what no longer matches the schema, then build what's missing.
 *
 *   npm run sync:indexes
 */
import mongoose from "mongoose";
import env from "../config/env.js";
import connectDb from "../connectDb.js";

import { SuperAdmin, HotelOwner } from "../models/userModel.js";
import Hotel from "../models/hotelModel.js";
import Table from "../models/tableModel.js";
import { Category, Ingredient, Dish } from "../models/dishModel.js";
import Offer from "../models/offerModel.js";
import Order from "../models/orderModel.js";
import Customer from "../models/customerModel.js";
import Bill from "../models/billModel.js";

const MODELS = [
  SuperAdmin, HotelOwner, Hotel, Table,
  Category, Ingredient, Dish, Offer, Order, Customer, Bill,
];

const run = async () => {
  await connectDb(env.DATABASE_URL);
  console.log(`\nSyncing indexes on "${env.DATABASE_NAME}"…\n`);

  for (const Model of MODELS) {
    try {
      const dropped = await Model.syncIndexes();
      const name = Model.modelName.padEnd(12);
      console.log(
        dropped.length > 0
          ? `  ${name} rebuilt (dropped ${dropped.join(", ")})`
          : `  ${name} up to date`
      );
    } catch (err) {
      // A unique index cannot be built over data that already violates it.
      // Say which, rather than failing the whole run silently.
      console.error(`  ${Model.modelName.padEnd(12)} FAILED — ${err.message}`);
    }
  }

  console.log("");
  await mongoose.connection.close();
  process.exit(0);
};

run().catch(async (err) => {
  console.error("\nIndex sync failed:", err.message);
  await mongoose.connection.close().catch(() => {});
  process.exit(1);
});
