/**
 * A compact portrait of one restaurant, assembled for the assistant.
 *
 * This is what makes the chat *personalised* rather than a chatbot that has
 * read a menu. It is built from real queries every time, and it is the only
 * route by which facts about the restaurant reach the model — the model never
 * touches the database, so it can never quote a revenue figure that was not
 * computed here.
 *
 * The brief is deliberately small. Tools (see `assistant.js`) exist for the
 * deep questions; this is the standing knowledge an assistant should simply
 * *have*, the way a good manager knows their own floor without looking it up.
 */
import mongoose from "mongoose";
import Bill from "../../models/billModel.js";
import Table from "../../models/tableModel.js";
import Order from "../../models/orderModel.js";
import Hotel from "../../models/hotelModel.js";
import { Dish, Ingredient } from "../../models/dishModel.js";
import { BILL_STATUS, ORDER_STATUS } from "../../utils/constant.js";

const oid = (value) => new mongoose.Types.ObjectId(String(value));
const round = (value) => Math.round((Number(value) || 0) * 100) / 100;

const startOfDay = (offsetDays = 0) => {
  const date = new Date();
  date.setHours(0, 0, 0, 0);
  date.setDate(date.getDate() - offsetDays);
  return date;
};

/** Settled takings between two dates. */
const takings = async (hotelId, from, to) => {
  const [row] = await Bill.aggregate([
    {
      $match: {
        hotelId: oid(hotelId),
        status: BILL_STATUS.PAID,
        settledAt: { $gte: from, ...(to ? { $lte: to } : {}) },
      },
    },
    {
      $group: {
        _id: null,
        revenue: { $sum: "$finalAmount" },
        covers: { $sum: 1 },
      },
    },
  ]);

  return {
    revenue: round(row?.revenue ?? 0),
    covers: row?.covers ?? 0,
    averageBill: row?.covers ? round(row.revenue / row.covers) : 0,
  };
};

/** Best sellers over a window, by units sold. */
const bestSellers = async (hotelId, since, limit = 8) => {
  const rows = await Bill.aggregate([
    { $match: { hotelId: oid(hotelId), status: BILL_STATUS.PAID, settledAt: { $gte: since } } },
    { $unwind: "$orderedItems" },
    {
      $group: {
        _id: "$orderedItems.name",
        units: { $sum: "$orderedItems.quantity" },
        revenue: { $sum: "$orderedItems.lineTotal" },
      },
    },
    { $sort: { units: -1 } },
    { $limit: limit },
  ]);

  return rows
    .filter((row) => row._id)
    .map((row) => ({ dish: row._id, units: row.units, revenue: round(row.revenue) }));
};

/** Which weekdays and hours actually earn, so advice can be timed. */
const tradingPattern = async (hotelId, since) => {
  const rows = await Bill.aggregate([
    { $match: { hotelId: oid(hotelId), status: BILL_STATUS.PAID, settledAt: { $gte: since } } },
    {
      $group: {
        // Mongo weekdays are 1=Sunday.
        _id: { weekday: { $dayOfWeek: "$settledAt" }, hour: { $hour: "$settledAt" } },
        revenue: { $sum: "$finalAmount" },
        covers: { $sum: 1 },
      },
    },
  ]);

  const names = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
  const byDay = new Map();
  const byHour = new Map();

  for (const row of rows) {
    const day = names[row._id.weekday - 1];
    byDay.set(day, (byDay.get(day) ?? 0) + row.revenue);
    byHour.set(row._id.hour, (byHour.get(row._id.hour) ?? 0) + row.covers);
  }

  const sortedDays = [...byDay.entries()].sort((a, b) => b[1] - a[1]);
  const sortedHours = [...byHour.entries()].sort((a, b) => b[1] - a[1]);

  return {
    busiestDays: sortedDays.slice(0, 2).map(([day, revenue]) => ({ day, revenue: round(revenue) })),
    quietestDays: sortedDays.slice(-2).map(([day, revenue]) => ({ day, revenue: round(revenue) })),
    peakHours: sortedHours.slice(0, 3).map(([hour, covers]) => ({
      hour: `${String(hour).padStart(2, "0")}:00`,
      covers,
    })),
  };
};

/**
 * The standing brief.
 *
 * Everything here is a fact the model may state. Anything absent, it must ask
 * a tool for or say it does not know.
 */
export const buildHotelBrief = async (hotelId) => {
  const since30 = startOfDay(30);
  const since90 = startOfDay(90);

  const [
    hotel,
    today,
    yesterday,
    last7,
    previous7,
    last30,
    sellers,
    pattern,
    dishes,
    tables,
    liveOrders,
    lowStock,
    openBills,
  ] = await Promise.all([
    Hotel.findById(hotelId).lean(),
    takings(hotelId, startOfDay(0)),
    takings(hotelId, startOfDay(1), startOfDay(0)),
    takings(hotelId, startOfDay(7)),
    takings(hotelId, startOfDay(14), startOfDay(7)),
    takings(hotelId, since30),
    bestSellers(hotelId, since30),
    tradingPattern(hotelId, since90),
    Dish.find({ hotelId, isDeleted: { $ne: true } })
      .select("name price category available")
      .populate("category", "name")
      .lean(),
    Table.find({ hotelId }).select("sequence status seats").lean(),
    Order.countDocuments({
      hotelId,
      status: { $in: [ORDER_STATUS.PENDING, ORDER_STATUS.PREPARING, ORDER_STATUS.READY] },
    }),
    /* Both fields are nullable, and `null <= null` is true in Mongo — without
       the existence guards this returns the entire pantry as "low". */
    Ingredient.find({
      hotelId,
      stockQuantity: { $ne: null },
      lowStockThreshold: { $ne: null },
      $expr: { $lte: ["$stockQuantity", "$lowStockThreshold"] },
    })
      .select("name stockQuantity unit")
      .limit(10)
      .lean(),
    Bill.countDocuments({ hotelId, status: BILL_STATUS.UNPAID }),
  ]);

  const menuByCategory = {};
  for (const dish of dishes) {
    const key = dish.category?.name ?? "Uncategorised";
    (menuByCategory[key] ??= []).push({
      name: dish.name,
      price: dish.price,
      ...(dish.available === false ? { unavailable: true } : {}),
    });
  }

  const weekChange =
    previous7.revenue > 0
      ? Math.round(((last7.revenue - previous7.revenue) / previous7.revenue) * 100)
      : null;

  return {
    restaurant: {
      name: hotel?.name ?? "This restaurant",
      location: hotel?.location ?? null,
      description: hotel?.description ?? null,
      phone: hotel?.phone ?? null,
      currency: hotel?.billing?.currencySymbol ?? "₹",
      taxRatePercent: hotel?.billing?.taxRatePercent ?? 0,
      serviceChargePercent: hotel?.billing?.serviceChargePercent ?? 0,
    },
    trading: {
      today,
      yesterday,
      last7Days: last7,
      previous7Days: previous7,
      weekOnWeekPercent: weekChange,
      last30Days: last30,
    },
    pattern,
    bestSellersLast30Days: sellers,
    menu: {
      dishCount: dishes.length,
      categories: Object.keys(menuByCategory),
      byCategory: menuByCategory,
    },
    floor: {
      tables: tables.length,
      seated: tables.filter((table) => table.status === "occupied").length,
      free: tables.filter((table) => table.status === "free").length,
      liveOrders,
      unpaidBills: openBills,
    },
    lowStock: lowStock.map((item) => ({
      name: item.name,
      remaining: item.stockQuantity,
      unit: item.unit,
    })),
  };
};

export default buildHotelBrief;
