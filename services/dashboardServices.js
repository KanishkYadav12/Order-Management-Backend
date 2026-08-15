import mongoose from "mongoose";
import Bill from "../models/billModel.js";
import Order from "../models/orderModel.js";
import Table from "../models/tableModel.js";
import { Ingredient } from "../models/dishModel.js";
import { BILL_STATUS, ORDER_STATUS, TABLE_STATUS } from "../utils/constant.js";
import { ValidationError } from "../utils/errorHandler.js";

/**
 * Dashboard analytics.
 *
 * Computed with aggregation pipelines rather than by loading every bill for
 * the month into Node and reducing over it — the previous approach grew
 * linearly with sales volume and would fall over on a busy restaurant.
 */

const startOfDay = (date) => {
  const d = new Date(date);
  d.setHours(0, 0, 0, 0);
  return d;
};

const startOfMonth = (date = new Date()) =>
  new Date(date.getFullYear(), date.getMonth(), 1);

export const getDashboardStatsService = async (hotelId, range = {}) => {
  if (!hotelId) throw new ValidationError("Missing restaurant.");

  const hotelObjectId = new mongoose.Types.ObjectId(String(hotelId));

  const now = new Date();
  const from = range.from ? new Date(range.from) : startOfMonth(now);
  const to = range.to ? new Date(range.to) : now;
  const todayStart = startOfDay(now);

  const paidInRange = {
    hotelId: hotelObjectId,
    status: BILL_STATUS.PAID,
    createdAt: { $gte: from, $lte: to },
  };

  const [
    dailySeries,
    periodTotals,
    todayTotals,
    topDishes,
    paymentMix,
    tableStates,
    liveOrders,
    lowStock,
    prepTime,
  ] = await Promise.all([
    // Revenue and covers per day, for the chart.
    Bill.aggregate([
      { $match: paidInRange },
      {
        $group: {
          _id: {
            $dateToString: { format: "%Y-%m-%d", date: "$createdAt" },
          },
          revenue: { $sum: "$finalAmount" },
          bills: { $sum: 1 },
          tax: { $sum: "$totalTax" },
          discount: { $sum: "$totalDiscount" },
        },
      },
      { $sort: { _id: 1 } },
    ]),

    Bill.aggregate([
      { $match: paidInRange },
      {
        $group: {
          _id: null,
          revenue: { $sum: "$finalAmount" },
          bills: { $sum: 1 },
          tax: { $sum: "$totalTax" },
          discount: { $sum: "$totalDiscount" },
          averageTicket: { $avg: "$finalAmount" },
        },
      },
    ]),

    Bill.aggregate([
      {
        $match: {
          hotelId: hotelObjectId,
          status: BILL_STATUS.PAID,
          createdAt: { $gte: todayStart },
        },
      },
      {
        $group: {
          _id: null,
          revenue: { $sum: "$finalAmount" },
          bills: { $sum: 1 },
          averageTicket: { $avg: "$finalAmount" },
        },
      },
    ]),

    // Best sellers by quantity, with the revenue each contributed.
    Bill.aggregate([
      { $match: paidInRange },
      { $unwind: "$orderedItems" },
      {
        $group: {
          _id: "$orderedItems.dishId",
          name: { $first: "$orderedItems.name" },
          totalQuantity: { $sum: "$orderedItems.quantity" },
          totalRevenue: { $sum: "$orderedItems.lineTotal" },
        },
      },
      { $sort: { totalQuantity: -1 } },
      { $limit: 10 },
      {
        $lookup: {
          from: "dishes",
          localField: "_id",
          foreignField: "_id",
          as: "dish",
        },
      },
      {
        $project: {
          id: "$_id",
          name: { $ifNull: [{ $first: "$dish.name" }, "$name"] },
          logo: { $first: "$dish.logo" },
          price: { $first: "$dish.price" },
          totalQuantity: 1,
          totalRevenue: 1,
        },
      },
    ]),

    Bill.aggregate([
      { $match: paidInRange },
      { $unwind: "$payments" },
      {
        $group: {
          _id: "$payments.method",
          amount: { $sum: "$payments.amount" },
          count: { $sum: 1 },
        },
      },
      { $sort: { amount: -1 } },
    ]),

    Table.aggregate([
      { $match: { hotelId: hotelObjectId, isDeleted: { $ne: true } } },
      { $group: { _id: "$status", count: { $sum: 1 } } },
    ]),

    Order.aggregate([
      {
        $match: {
          hotelId: hotelObjectId,
          status: {
            $in: [
              ORDER_STATUS.PENDING,
              ORDER_STATUS.PREPARING,
              ORDER_STATUS.READY,
            ],
          },
        },
      },
      { $group: { _id: "$status", count: { $sum: 1 } } },
    ]),

    Ingredient.countDocuments({
      hotelId: hotelObjectId,
      isDeleted: false,
      stockQuantity: { $ne: null },
      lowStockThreshold: { $ne: null },
      $expr: { $lte: ["$stockQuantity", "$lowStockThreshold"] },
    }),

    // Median-ish prep time: mean minutes from confirmation to ready.
    Order.aggregate([
      {
        $match: {
          hotelId: hotelObjectId,
          confirmedAt: { $ne: null },
          readyAt: { $ne: null },
          createdAt: { $gte: from },
        },
      },
      {
        $project: {
          minutes: {
            $divide: [{ $subtract: ["$readyAt", "$confirmedAt"] }, 60000],
          },
        },
      },
      { $group: { _id: null, average: { $avg: "$minutes" } } },
    ]),
  ]);

  const period = periodTotals[0] ?? {};
  const today = todayTotals[0] ?? {};

  const byStatus = (rows) =>
    rows.reduce((acc, row) => ({ ...acc, [row._id]: row.count }), {});

  // Keys the existing dashboard reads are preserved alongside the new ones.
  const revenueByDate = {};
  const customersByDate = {};
  for (const day of dailySeries) {
    revenueByDate[day._id] = day.revenue;
    customersByDate[day._id] = day.bills;
  }

  return {
    range: { from, to },

    revenue: {
      today: today.revenue ?? 0,
      monthly: period.revenue ?? 0,
      tax: period.tax ?? 0,
      discount: period.discount ?? 0,
      averageTicket: Math.round((period.averageTicket ?? 0) * 100) / 100,
    },

    customers: {
      today: today.bills ?? 0,
      monthly: period.bills ?? 0,
    },

    revenueByDate,
    customersByDate,
    series: dailySeries.map((day) => ({
      date: day._id,
      revenue: day.revenue,
      bills: day.bills,
      tax: day.tax,
      discount: day.discount,
    })),

    thisMonthDishes: topDishes,
    topDishes,

    paymentMix,

    tables: {
      total: tableStates.reduce((sum, row) => sum + row.count, 0),
      free: byStatus(tableStates)[TABLE_STATUS.FREE] ?? 0,
      occupied: byStatus(tableStates)[TABLE_STATUS.OCCUPIED] ?? 0,
      reserved: byStatus(tableStates)[TABLE_STATUS.RESERVED] ?? 0,
    },

    kitchen: {
      pending: byStatus(liveOrders)[ORDER_STATUS.PENDING] ?? 0,
      preparing: byStatus(liveOrders)[ORDER_STATUS.PREPARING] ?? 0,
      ready: byStatus(liveOrders)[ORDER_STATUS.READY] ?? 0,
      averagePrepMinutes: Math.round((prepTime[0]?.average ?? 0) * 10) / 10,
    },

    alerts: {
      lowStockIngredients: lowStock,
    },
  };
};
