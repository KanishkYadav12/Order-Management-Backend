/**
 * Seeds a complete, believable restaurant so every screen has something real
 * to show — including 90 days of settled bills, which is what the menu
 * engineering, forecasting, basket-analysis and anomaly reports run on.
 *
 * Bills are built through the app's own `recalculateBill`, so the seeded
 * money matches exactly what the running system would produce. Nothing here
 * is hand-computed.
 *
 *   npm run seed:demo          seed into an empty database
 *   npm run seed:demo -- --reset   wipe this app's collections first
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
import { recalculateBill, formatInvoiceNumber } from "../services/billingEngine.js";
import { ROLES, ORDER_STATUS, BILL_STATUS, TABLE_STATUS } from "../utils/constant.js";

const RESET = process.argv.includes("--reset");

/* ── Credentials ──────────────────────────────────────────────────────────
   Deliberately in plain sight: this is demo data. Change them, or delete
   these accounts, before the system holds anything real. */
const ACCOUNTS = [
  { role: ROLES.SUPER_ADMIN, name: "Platform Admin", email: "admin@qrdine.app", password: "Admin@2026" },
  { role: ROLES.HOTEL_OWNER, name: "Kanishk Yadav", email: "owner@spicegarden.in", password: "Owner@2026" },
];

const INGREDIENTS = [
  { name: "Paneer", unit: "kg", costPerUnit: 320, stockQuantity: 12, lowStockThreshold: 5 },
  { name: "Chicken", unit: "kg", costPerUnit: 240, stockQuantity: 18, lowStockThreshold: 8 },
  { name: "Basmati Rice", unit: "kg", costPerUnit: 110, stockQuantity: 40, lowStockThreshold: 15 },
  { name: "Wheat Flour", unit: "kg", costPerUnit: 45, stockQuantity: 25, lowStockThreshold: 10 },
  { name: "Butter", unit: "kg", costPerUnit: 480, stockQuantity: 4, lowStockThreshold: 5 },
  { name: "Cream", unit: "l", costPerUnit: 260, stockQuantity: 3, lowStockThreshold: 4 },
  { name: "Tomato", unit: "kg", costPerUnit: 40, stockQuantity: 22, lowStockThreshold: 8 },
  { name: "Onion", unit: "kg", costPerUnit: 35, stockQuantity: 30, lowStockThreshold: 10 },
  { name: "Potato", unit: "kg", costPerUnit: 28, stockQuantity: 26, lowStockThreshold: 10 },
  { name: "Mixed Spices", unit: "kg", costPerUnit: 620, stockQuantity: 6, lowStockThreshold: 2 },
  { name: "Cooking Oil", unit: "l", costPerUnit: 140, stockQuantity: 20, lowStockThreshold: 8 },
  { name: "Milk", unit: "l", costPerUnit: 62, stockQuantity: 15, lowStockThreshold: 6 },
  { name: "Sugar", unit: "kg", costPerUnit: 48, stockQuantity: 14, lowStockThreshold: 5 },
  { name: "Tea Leaves", unit: "kg", costPerUnit: 420, stockQuantity: 2, lowStockThreshold: 3 },
  { name: "Coffee Beans", unit: "kg", costPerUnit: 780, stockQuantity: 3, lowStockThreshold: 2 },
  { name: "Lemon", unit: "kg", costPerUnit: 60, stockQuantity: 8, lowStockThreshold: 3 },
];

const CATEGORIES = [
  { name: "Starters", displayOrder: 1, description: "Something to begin with" },
  { name: "Main Course", displayOrder: 2, description: "Curries and grills" },
  { name: "Breads", displayOrder: 3, description: "From the tandoor" },
  { name: "Rice & Biryani", displayOrder: 4, description: "Slow-cooked and fragrant" },
  { name: "Desserts", displayOrder: 5, description: "To finish" },
  { name: "Beverages", displayOrder: 6, description: "Hot and cold" },
];

/**
 * `weight` drives how often a dish appears in generated bills, so the sales
 * mix looks like a real menu rather than a uniform distribution — which is
 * what makes the menu-engineering quadrants meaningful.
 */
const DISHES = [
  // Starters
  { name: "Paneer Tikka", category: "Starters", price: 320, weight: 9, veg: true, spice: "medium", recipe: [["Paneer", 0.2], ["Mixed Spices", 0.01], ["Onion", 0.05]] },
  { name: "Chicken Tikka", category: "Starters", price: 380, weight: 10, veg: false, spice: "medium", recipe: [["Chicken", 0.25], ["Mixed Spices", 0.012], ["Onion", 0.05]] },
  { name: "Crispy Corn", category: "Starters", price: 240, weight: 5, veg: true, spice: "mild", recipe: [["Cooking Oil", 0.05], ["Mixed Spices", 0.005]] },
  { name: "Hara Bhara Kebab", category: "Starters", price: 260, weight: 2, veg: true, spice: "mild", recipe: [["Potato", 0.15], ["Mixed Spices", 0.008], ["Cooking Oil", 0.04]] },
  { name: "Fish Amritsari", category: "Starters", price: 420, weight: 2, veg: false, spice: "hot", recipe: [["Cooking Oil", 0.06], ["Mixed Spices", 0.015]] },

  // Main Course
  { name: "Butter Chicken", category: "Main Course", price: 460, weight: 14, veg: false, spice: "mild", recipe: [["Chicken", 0.3], ["Butter", 0.04], ["Cream", 0.06], ["Tomato", 0.15], ["Mixed Spices", 0.012]] },
  { name: "Paneer Butter Masala", category: "Main Course", price: 400, weight: 11, veg: true, spice: "mild", recipe: [["Paneer", 0.22], ["Butter", 0.035], ["Cream", 0.05], ["Tomato", 0.14]] },
  { name: "Dal Makhani", category: "Main Course", price: 280, weight: 10, veg: true, spice: "mild", recipe: [["Butter", 0.025], ["Cream", 0.04], ["Tomato", 0.08]] },
  { name: "Kadai Chicken", category: "Main Course", price: 440, weight: 6, veg: false, spice: "hot", recipe: [["Chicken", 0.28], ["Onion", 0.12], ["Tomato", 0.12], ["Mixed Spices", 0.014]] },
  { name: "Palak Paneer", category: "Main Course", price: 360, weight: 5, veg: true, spice: "mild", recipe: [["Paneer", 0.18], ["Cream", 0.03]] },
  { name: "Mutton Rogan Josh", category: "Main Course", price: 560, weight: 2, veg: false, spice: "hot", recipe: [["Mixed Spices", 0.02], ["Onion", 0.15], ["Cooking Oil", 0.05]] },
  { name: "Malai Kofta", category: "Main Course", price: 380, weight: 2, veg: true, spice: "mild", recipe: [["Paneer", 0.15], ["Cream", 0.06], ["Potato", 0.1]] },

  // Breads
  { name: "Butter Naan", category: "Breads", price: 70, weight: 20, veg: true, spice: "none", recipe: [["Wheat Flour", 0.09], ["Butter", 0.008]] },
  { name: "Garlic Naan", category: "Breads", price: 90, weight: 14, veg: true, spice: "none", recipe: [["Wheat Flour", 0.09], ["Butter", 0.01]] },
  { name: "Tandoori Roti", category: "Breads", price: 45, weight: 11, veg: true, spice: "none", recipe: [["Wheat Flour", 0.07]] },
  { name: "Laccha Paratha", category: "Breads", price: 85, weight: 4, veg: true, spice: "none", recipe: [["Wheat Flour", 0.1], ["Cooking Oil", 0.02]] },

  // Rice
  { name: "Chicken Biryani", category: "Rice & Biryani", price: 420, weight: 12, veg: false, spice: "medium", recipe: [["Basmati Rice", 0.2], ["Chicken", 0.22], ["Mixed Spices", 0.015], ["Onion", 0.08]] },
  { name: "Veg Biryani", category: "Rice & Biryani", price: 320, weight: 6, veg: true, spice: "medium", recipe: [["Basmati Rice", 0.2], ["Mixed Spices", 0.012], ["Onion", 0.08]] },
  { name: "Jeera Rice", category: "Rice & Biryani", price: 180, weight: 7, veg: true, spice: "none", recipe: [["Basmati Rice", 0.15], ["Cooking Oil", 0.02]] },
  { name: "Steamed Rice", category: "Rice & Biryani", price: 140, weight: 5, veg: true, spice: "none", recipe: [["Basmati Rice", 0.15]] },

  // Desserts
  { name: "Gulab Jamun", category: "Desserts", price: 160, weight: 7, veg: true, spice: "none", recipe: [["Milk", 0.1], ["Sugar", 0.08]] },
  { name: "Rasmalai", category: "Desserts", price: 180, weight: 4, veg: true, spice: "none", recipe: [["Milk", 0.15], ["Sugar", 0.06], ["Cream", 0.03]] },
  { name: "Gajar Halwa", category: "Desserts", price: 190, weight: 2, veg: true, spice: "none", recipe: [["Milk", 0.12], ["Sugar", 0.07], ["Butter", 0.02]] },

  // Beverages
  { name: "Masala Chai", category: "Beverages", price: 60, weight: 15, veg: true, spice: "none", recipe: [["Tea Leaves", 0.008], ["Milk", 0.12], ["Sugar", 0.015]] },
  { name: "Filter Coffee", category: "Beverages", price: 80, weight: 8, veg: true, spice: "none", recipe: [["Coffee Beans", 0.012], ["Milk", 0.12], ["Sugar", 0.012]] },
  { name: "Sweet Lassi", category: "Beverages", price: 120, weight: 6, veg: true, spice: "none", recipe: [["Milk", 0.2], ["Sugar", 0.03]] },
  { name: "Fresh Lime Soda", category: "Beverages", price: 90, weight: 5, veg: true, spice: "none", recipe: [["Lemon", 0.06], ["Sugar", 0.02]] },
];

const GUEST_NAMES = [
  "Aarav", "Diya", "Vivaan", "Ananya", "Aditya", "Ishita", "Arjun", "Kavya",
  "Reyansh", "Saanvi", "Vihaan", "Anika", "Kabir", "Myra", "Rohan", "Aisha",
];

const pick = (list) => list[Math.floor(Math.random() * list.length)];
const between = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;

/** Weekend-heavy demand, so the day-of-week forecaster has a real signal. */
const WEEKDAY_LOAD = [1.3, 0.65, 0.72, 0.85, 0.95, 1.35, 1.55]; // Sun … Sat

const run = async () => {
  await connectDb(env.DATABASE_URL);
  console.log(`\nSeeding "${env.DATABASE_NAME}"…\n`);

  if (RESET) {
    for (const model of [SuperAdmin, HotelOwner, Hotel, Table, Category, Ingredient, Dish, Offer, Order, Customer, Bill]) {
      await model.deleteMany({});
    }
    console.log("  cleared existing data");
  }

  /* ── Owner and hotel ─────────────────────────────────────────────────── */
  const ownerSpec = ACCOUNTS.find((a) => a.role === ROLES.HOTEL_OWNER);
  const owner = await HotelOwner.create({
    name: ownerSpec.name,
    email: ownerSpec.email,
    password: ownerSpec.password,
    role: ROLES.HOTEL_OWNER,
    phone: "+91 98200 11223",
    isApproved: true,
    isVerified: true,
    membershipExpires: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
  });

  const hotel = await Hotel.create({
    name: "Spice Garden",
    location: "12 Linking Road, Bandra West, Mumbai 400050",
    phone: "+91 22 2640 1234",
    email: "hello@spicegarden.in",
    ownerId: owner._id,
    description: "North Indian kitchen and tandoor since 1998.",
    billing: {
      gstin: "27AABCS1429B1ZX",
      taxRatePercent: 5,
      pricesIncludeTax: false,
      serviceChargePercent: 10,
      currency: "INR",
      currencySymbol: "₹",
      roundOffEnabled: true,
      invoicePrefix: "SG",
      invoiceCounter: 0,
      footerNote: "Thank you for dining with us. GST included as shown.",
    },
  });

  owner.hotelId = hotel._id;
  await owner.save({ validateBeforeSave: false });
  console.log(`  hotel        Spice Garden`);

  /* ── Remaining accounts ──────────────────────────────────────────────── */
  for (const spec of ACCOUNTS) {
    if (spec.role === ROLES.HOTEL_OWNER) continue;

    const Model = spec.role === ROLES.SUPER_ADMIN ? SuperAdmin : HotelOwner;
    await Model.create({
      name: spec.name,
      email: spec.email,
      password: spec.password,
      role: spec.role,
      isApproved: true,
      isVerified: true,
      ...(spec.role === ROLES.SUPER_ADMIN
        ? {}
        : { hotelId: hotel._id, invitedBy: owner._id }),
    });
  }
  console.log(`  accounts     ${ACCOUNTS.length}`);

  /* ── Menu ────────────────────────────────────────────────────────────── */
  const ingredients = await Ingredient.insertMany(
    INGREDIENTS.map((i) => ({ ...i, hotelId: hotel._id }))
  );
  const ingredientByName = new Map(ingredients.map((i) => [i.name, i]));

  const categories = await Category.insertMany(
    CATEGORIES.map((c) => ({ ...c, hotelId: hotel._id }))
  );
  const categoryByName = new Map(categories.map((c) => [c.name, c]));

  const dishes = await Dish.insertMany(
    DISHES.map((d) => ({
      name: d.name,
      price: d.price,
      hotelId: hotel._id,
      category: categoryByName.get(d.category)._id,
      isVegetarian: d.veg,
      spiceLevel: d.spice,
      preparationTime: `${between(8, 25)} minutes`,
      description: `${d.name}, made to order.`,
      ingredients: d.recipe.map(([name]) => ingredientByName.get(name)._id),
      // The recipe is what makes margin a measurement rather than a guess.
      recipe: d.recipe.map(([name, quantity]) => ({
        ingredientId: ingredientByName.get(name)._id,
        quantity,
      })),
      bestSeller: d.weight >= 12,
    }))
  );
  const dishByName = new Map(dishes.map((d) => [d.name, d]));
  const weightByName = new Map(DISHES.map((d) => [d.name, d.weight]));
  console.log(`  menu         ${categories.length} categories, ${dishes.length} dishes, ${ingredients.length} ingredients`);

  /* ── Offers ──────────────────────────────────────────────────────────── */
  const [weekendOffer] = await Offer.create([
    {
      name: "10% off bills over ₹1,500",
      type: "global",
      discountType: "percent",
      value: 10,
      appliedAbove: 1500,
      hotelId: hotel._id,
      description: "Applied automatically on larger tables.",
    },
    {
      name: "₹40 off Butter Naan",
      type: "specific",
      discountType: "amount",
      value: 40,
      appliedOn: [dishByName.get("Butter Naan")._id],
      hotelId: hotel._id,
    },
  ]);
  await Dish.updateOne(
    { _id: dishByName.get("Butter Naan")._id },
    { $set: { offer: (await Offer.findOne({ name: "₹40 off Butter Naan" }))._id } }
  );
  console.log(`  offers       2`);

  /* ── Tables ──────────────────────────────────────────────────────────── */
  const tables = await Table.insertMany(
    Array.from({ length: 14 }, (_, index) => ({
      sequence: index + 1,
      capacity: index < 8 ? 4 : index < 12 ? 6 : 2,
      position: index < 6 ? "Ground floor" : index < 12 ? "First floor" : "Terrace",
      hotelId: hotel._id,
      status: TABLE_STATUS.FREE,
    }))
  );
  console.log(`  tables       ${tables.length}`);

  /* ── 90 days of settled bills ────────────────────────────────────────── */
  const weightedMenu = [];
  for (const dish of dishes) {
    const weight = weightByName.get(dish.name) ?? 1;
    for (let i = 0; i < weight; i += 1) weightedMenu.push(dish);
  }

  const billDocs = [];
  let invoiceCounter = 0;
  const DAYS = 90;

  for (let ago = DAYS; ago >= 1; ago -= 1) {
    const day = new Date();
    day.setDate(day.getDate() - ago);
    day.setHours(0, 0, 0, 0);

    let count = Math.round(18 * WEEKDAY_LOAD[day.getDay()] * (0.85 + Math.random() * 0.3));

    // Two deliberate outliers so anomaly detection has something true to find.
    if (ago === 34) count = Math.round(count * 2.4); // a festival night
    if (ago === 17) count = Math.round(count * 0.25); // a closure

    for (let n = 0; n < count; n += 1) {
      const table = pick(tables);
      const itemCount = between(2, 6);

      const chosen = new Map();
      for (let i = 0; i < itemCount; i += 1) {
        const dish = pick(weightedMenu);
        chosen.set(dish._id.toString(), {
          dish,
          quantity: (chosen.get(dish._id.toString())?.quantity ?? 0) + between(1, 2),
        });
      }

      const items = [...chosen.values()];

      // Lunch and dinner services rather than a uniform spread across the day.
      const hour = Math.random() < 0.42 ? between(12, 15) : between(19, 22);
      const at = new Date(day);
      at.setHours(hour, between(0, 59), between(0, 59), 0);

      const subtotalGuess = items.reduce(
        (sum, entry) => sum + entry.dish.price * entry.quantity,
        0
      );
      const useOffer = subtotalGuess >= 1500 && Math.random() < 0.55;

      // Computed by the app's own engine, so seeded money is real money.
      const totals = recalculateBill({
        items,
        globalOffer: useOffer ? weekendOffer : null,
        customDiscount: Math.random() < 0.08 ? between(20, 80) : 0,
        billingSettings: hotel.billing,
        at,
      });

      invoiceCounter += 1;
      const method = Math.random() < 0.55 ? "upi" : Math.random() < 0.6 ? "card" : "cash";

      billDocs.push({
        ...totals,
        invoiceNumber: formatInvoiceNumber("SG", invoiceCounter, at),
        customerName: pick(GUEST_NAMES),
        tableId: table._id,
        hotelId: hotel._id,
        globalOffer: useOffer ? weekendOffer._id : null,
        status: BILL_STATUS.PAID,
        amountPaid: totals.finalAmount,
        payments: [
          { method, amount: totals.finalAmount, receivedAt: at, receivedBy: owner._id },
        ],
        settledAt: at,
        createdAt: at,
        updatedAt: at,
      });
    }
  }

  // `timestamps: false` so the backdated createdAt survives — otherwise
  // Mongoose overwrites every one of them with "now" and the history is flat.
  await Bill.insertMany(billDocs, { timestamps: false, ordered: false });
  await Hotel.updateOne(
    { _id: hotel._id },
    { $set: { "billing.invoiceCounter": invoiceCounter } }
  );

  const revenue = billDocs.reduce((sum, b) => sum + b.finalAmount, 0);
  console.log(`  bills        ${billDocs.length} over ${DAYS} days (₹${Math.round(revenue).toLocaleString("en-IN")})`);

  /* ── Live service ────────────────────────────────────────────────────── */
  const liveTables = tables.slice(0, 4);
  const statuses = [
    ORDER_STATUS.PENDING,
    ORDER_STATUS.PREPARING,
    ORDER_STATUS.READY,
    ORDER_STATUS.COMPLETED,
  ];

  for (const [index, table] of liveTables.entries()) {
    const customer = await Customer.create({
      name: pick(GUEST_NAMES),
      hotelId: hotel._id,
      tableId: table._id,
    });

    const picked = Array.from({ length: between(2, 4) }, () => pick(weightedMenu));
    const placedAt = new Date(Date.now() - between(5, 40) * 60 * 1000);

    await Order.create({
      customerId: customer._id,
      tableId: table._id,
      hotelId: hotel._id,
      status: statuses[index],
      isFirstOrder: true,
      confirmedAt: placedAt,
      dishes: picked.map((dish) => ({
        dishId: dish._id,
        quantity: between(1, 2),
        unitPrice: dish.price,
      })),
    });

    await Table.updateOne(
      { _id: table._id },
      {
        $set: {
          status: TABLE_STATUS.OCCUPIED,
          customer: customer._id,
          occupiedAt: placedAt,
          covers: between(2, 5),
        },
      }
    );
  }
  console.log(`  live service ${liveTables.length} tables seated with open orders`);

  /* ── Summary ─────────────────────────────────────────────────────────── */
  console.log("\n  Sign in at /login\n");
  console.log("  ROLE          EMAIL                          PASSWORD");
  console.log("  " + "─".repeat(64));
  for (const account of ACCOUNTS) {
    console.log(
      `  ${account.role.padEnd(13)} ${account.email.padEnd(30)} ${account.password}`
    );
  }
  console.log("\n  Change or delete these before this holds anything real.\n");

  await mongoose.connection.close();
  process.exit(0);
};

run().catch(async (err) => {
  console.error("\nSeed failed:", err.message);
  if (err.writeErrors?.length) console.error(err.writeErrors[0].errmsg);
  await mongoose.connection.close().catch(() => {});
  process.exit(1);
});
