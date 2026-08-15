import mongoose from "mongoose";
import Bill from "../../models/billModel.js";
import Order from "../../models/orderModel.js";
import { Dish } from "../../models/dishModel.js";
import { BILL_STATUS } from "../../utils/constant.js";
import { round2 } from "../billingEngine.js";

/**
 * Menu and demand intelligence.
 *
 * Deliberately **not** an LLM. Every figure here is a deterministic
 * calculation over the restaurant's own sales history — so it costs nothing
 * to run, needs no API key, works offline, has no rate limit, and returns the
 * same answer twice for the same data. A language model would be slower, less
 * accurate, and billable for exactly this arithmetic.
 *
 * The LLM layer sits on top of these numbers and only writes the prose.
 */

const oid = (value) => new mongoose.Types.ObjectId(String(value));

/* ── Menu engineering ─────────────────────────────────────────────────────
   The standard Kasavana–Smith matrix: classify each dish on popularity
   (units sold vs menu average) against margin contribution. Every restaurant
   consultant uses this; it just usually costs a consultant. */

const CLASSIFICATIONS = {
  star: {
    label: "Star",
    advice: "Popular and profitable. Keep the recipe and placement exactly as they are.",
  },
  plowhorse: {
    label: "Plowhorse",
    advice:
      "Sells well but earns little. Raise the price a little, or trim portion cost — demand can absorb it.",
  },
  puzzle: {
    label: "Puzzle",
    advice:
      "Profitable but nobody orders it. Rename it, move it up the menu, or have staff recommend it.",
  },
  dog: {
    label: "Dog",
    advice: "Low sales and low margin. Strong candidate to remove from the menu.",
  },
};

/**
 * Classifies every dish sold in the period.
 *
 * @param {string} hotelId
 * @param {{from?: Date, to?: Date}} range
 */
export const analyseMenu = async (hotelId, { from, to } = {}) => {
  const hotelObjectId = oid(hotelId);
  const since = from ?? new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
  const until = to ?? new Date();

  const sales = await Bill.aggregate([
    {
      $match: {
        hotelId: hotelObjectId,
        status: BILL_STATUS.PAID,
        createdAt: { $gte: since, $lte: until },
      },
    },
    { $unwind: "$orderedItems" },
    {
      $group: {
        _id: "$orderedItems.dishId",
        units: { $sum: "$orderedItems.quantity" },
        revenue: { $sum: "$orderedItems.lineTotal" },
        discountGiven: { $sum: "$orderedItems.discount" },
      },
    },
  ]);

  if (sales.length === 0) {
    return { period: { from: since, to: until }, items: [], summary: null };
  }

  const dishes = await Dish.find({
    _id: { $in: sales.map((row) => row._id) },
  })
    .populate("category", "name")
    .populate("recipe.ingredientId", "name costPerUnit");

  const dishById = new Map(dishes.map((dish) => [dish._id.toString(), dish]));

  /**
   * Portion cost from the recipe when it's been filled in.
   *
   * Without a recipe there is no true food cost, so margin is unknowable —
   * we fall back to a 30% assumption and flag it, rather than silently
   * presenting a guess as a measurement.
   */
  const portionCost = (dish) => {
    const recipe = dish?.recipe ?? [];
    const costed = recipe.filter(
      (line) => line.ingredientId?.costPerUnit != null && line.quantity != null
    );

    if (costed.length === 0) {
      return { cost: round2((dish?.price ?? 0) * 0.3), estimated: true };
    }

    const cost = costed.reduce(
      (sum, line) => sum + line.ingredientId.costPerUnit * line.quantity,
      0
    );
    return { cost: round2(cost), estimated: false };
  };

  const items = sales.map((row) => {
    const dish = dishById.get(row._id?.toString());
    const { cost, estimated } = portionCost(dish);
    const price = dish?.price ?? 0;
    const marginPerUnit = round2(price - cost);

    return {
      dishId: row._id,
      name: dish?.name ?? "Removed dish",
      category: dish?.category?.name ?? null,
      price,
      portionCost: cost,
      costIsEstimated: estimated,
      units: row.units,
      revenue: round2(row.revenue),
      discountGiven: round2(row.discountGiven),
      marginPerUnit,
      totalMargin: round2(marginPerUnit * row.units),
      marginPercent: price > 0 ? Math.round((marginPerUnit / price) * 100) : 0,
      isDeleted: dish?.isDeleted ?? true,
    };
  });

  // The thresholds are the menu's own averages — a dish is "popular" relative
  // to this restaurant, not to some external benchmark.
  const averageUnits =
    items.reduce((sum, item) => sum + item.units, 0) / items.length;
  const averageMargin =
    items.reduce((sum, item) => sum + item.marginPerUnit, 0) / items.length;

  // 70% of average is the conventional popularity line in this model.
  const popularityLine = averageUnits * 0.7;

  for (const item of items) {
    const popular = item.units >= popularityLine;
    const profitable = item.marginPerUnit >= averageMargin;

    item.classification = popular
      ? profitable
        ? "star"
        : "plowhorse"
      : profitable
        ? "puzzle"
        : "dog";
    item.label = CLASSIFICATIONS[item.classification].label;
    item.advice = CLASSIFICATIONS[item.classification].advice;
  }

  items.sort((a, b) => b.totalMargin - a.totalMargin);

  const byClass = (name) => items.filter((item) => item.classification === name);

  return {
    period: { from: since, to: until },
    thresholds: {
      averageUnits: round2(averageUnits),
      popularityLine: round2(popularityLine),
      averageMargin: round2(averageMargin),
    },
    items,
    summary: {
      totalRevenue: round2(items.reduce((sum, i) => sum + i.revenue, 0)),
      totalMargin: round2(items.reduce((sum, i) => sum + i.totalMargin, 0)),
      stars: byClass("star").length,
      plowhorses: byClass("plowhorse").length,
      puzzles: byClass("puzzle").length,
      dogs: byClass("dog").length,
      /** Dishes with no recipe, so their margin is a guess rather than a fact. */
      unpricedRecipes: items.filter((i) => i.costIsEstimated).length,
    },
    recommendations: [
      ...byClass("dog")
        .slice(0, 3)
        .map((item) => ({
          type: "remove",
          dishId: item.dishId,
          dish: item.name,
          reason: `${item.units} sold in the period at ₹${item.marginPerUnit} margin — the weakest on both counts.`,
        })),
      ...byClass("plowhorse")
        .slice(0, 3)
        .map((item) => ({
          type: "reprice",
          dishId: item.dishId,
          dish: item.name,
          reason: `${item.units} sold but only ₹${item.marginPerUnit} margin each. A ₹${Math.max(10, Math.round(item.price * 0.08))} rise adds roughly ₹${Math.round(item.units * Math.max(10, item.price * 0.08))} over the same period.`,
        })),
      ...byClass("puzzle")
        .slice(0, 3)
        .map((item) => ({
          type: "promote",
          dishId: item.dishId,
          dish: item.name,
          reason: `Earns ₹${item.marginPerUnit} a plate but only sold ${item.units}. Worth featuring.`,
        })),
    ],
  };
};

/* ── Demand forecasting ───────────────────────────────────────────────────
   Restaurant demand is dominated by day-of-week seasonality, so a
   day-of-week average beats a plain moving average by a wide margin, and
   needs no training, no model file and no inference cost. */

export const forecastDemand = async (hotelId, { days = 7, lookbackDays = 56 } = {}) => {
  const hotelObjectId = oid(hotelId);
  const since = new Date(Date.now() - lookbackDays * 24 * 60 * 60 * 1000);

  const history = await Bill.aggregate([
    {
      $match: {
        hotelId: hotelObjectId,
        status: BILL_STATUS.PAID,
        createdAt: { $gte: since },
      },
    },
    {
      $group: {
        _id: {
          date: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
          weekday: { $dayOfWeek: "$createdAt" },
        },
        covers: { $sum: 1 },
        revenue: { $sum: "$finalAmount" },
      },
    },
    { $sort: { "_id.date": 1 } },
  ]);

  if (history.length < 7) {
    return {
      ready: false,
      reason:
        "Not enough sales history yet. Forecasts need at least a week of settled bills.",
      daysOfHistory: history.length,
      forecast: [],
    };
  }

  // Group observed days by weekday (Mongo: 1 = Sunday).
  const byWeekday = new Map();
  for (const row of history) {
    const key = row._id.weekday;
    if (!byWeekday.has(key)) byWeekday.set(key, []);
    byWeekday.get(key).push({ covers: row.covers, revenue: row.revenue });
  }

  const mean = (values) =>
    values.length === 0 ? 0 : values.reduce((a, b) => a + b, 0) / values.length;

  const stdDev = (values) => {
    if (values.length < 2) return 0;
    const avg = mean(values);
    return Math.sqrt(mean(values.map((v) => (v - avg) ** 2)));
  };

  const WEEKDAY_NAMES = [
    "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday",
  ];

  const forecast = [];
  for (let offset = 1; offset <= days; offset += 1) {
    const date = new Date();
    date.setDate(date.getDate() + offset);
    const weekday = date.getDay() + 1; // align with Mongo's 1-based weekday

    const samples = byWeekday.get(weekday) ?? [];
    const covers = samples.map((s) => s.covers);
    const revenue = samples.map((s) => s.revenue);

    forecast.push({
      date: date.toISOString().split("T")[0],
      weekday: WEEKDAY_NAMES[date.getDay()],
      expectedCovers: Math.round(mean(covers)),
      expectedRevenue: round2(mean(revenue)),
      // ±1 SD gives a usable planning band without pretending to more
      // precision than 8 weeks of data supports.
      coversRange: {
        low: Math.max(0, Math.round(mean(covers) - stdDev(covers))),
        high: Math.round(mean(covers) + stdDev(covers)),
      },
      confidence:
        samples.length >= 6 ? "high" : samples.length >= 3 ? "medium" : "low",
      basedOnSamples: samples.length,
    });
  }

  return {
    ready: true,
    daysOfHistory: history.length,
    forecast,
    busiestDay: [...forecast].sort(
      (a, b) => b.expectedCovers - a.expectedCovers
    )[0],
    quietestDay: [...forecast].sort(
      (a, b) => a.expectedCovers - b.expectedCovers
    )[0],
  };
};

/**
 * Prep quantities for a given day, derived from the forecast and each dish's
 * historical share of covers.
 */
export const forecastPrep = async (hotelId, { date } = {}) => {
  const demand = await forecastDemand(hotelId, { days: 7 });
  if (!demand.ready) return { ready: false, reason: demand.reason, items: [] };

  const target = date
    ? demand.forecast.find((day) => day.date === date)
    : demand.forecast[0];

  if (!target) {
    return { ready: false, reason: "That date is outside the forecast window.", items: [] };
  }

  const hotelObjectId = oid(hotelId);
  const since = new Date(Date.now() - 56 * 24 * 60 * 60 * 1000);

  const [totals] = await Bill.aggregate([
    {
      $match: {
        hotelId: hotelObjectId,
        status: BILL_STATUS.PAID,
        createdAt: { $gte: since },
      },
    },
    { $count: "bills" },
  ]);

  const perDish = await Bill.aggregate([
    {
      $match: {
        hotelId: hotelObjectId,
        status: BILL_STATUS.PAID,
        createdAt: { $gte: since },
      },
    },
    { $unwind: "$orderedItems" },
    {
      $group: {
        _id: "$orderedItems.dishId",
        name: { $first: "$orderedItems.name" },
        units: { $sum: "$orderedItems.quantity" },
      },
    },
    { $sort: { units: -1 } },
    { $limit: 40 },
  ]);

  const billCount = totals?.bills ?? 1;

  return {
    ready: true,
    date: target.date,
    weekday: target.weekday,
    expectedCovers: target.expectedCovers,
    confidence: target.confidence,
    items: perDish.map((row) => ({
      dishId: row._id,
      name: row.name,
      perCover: round2(row.units / billCount),
      suggestedPrep: Math.ceil((row.units / billCount) * target.expectedCovers),
    })),
  };
};

/* ── Basket analysis ──────────────────────────────────────────────────────
   Which dishes get ordered together. This is what powers a genuinely useful
   upsell prompt — "people who ordered this also ordered that", computed from
   the restaurant's own tickets rather than guessed by a model. */

export const analyseBaskets = async (hotelId, { minSupport = 3 } = {}) => {
  const hotelObjectId = oid(hotelId);
  const since = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);

  const bills = await Bill.find({
    hotelId: hotelObjectId,
    status: BILL_STATUS.PAID,
    createdAt: { $gte: since },
  })
    .select("orderedItems")
    .lean();

  if (bills.length < 10) {
    return { ready: false, reason: "Not enough settled bills yet.", pairs: [] };
  }

  const itemCounts = new Map();
  const pairCounts = new Map();
  const names = new Map();

  for (const bill of bills) {
    const ids = [
      ...new Set(
        (bill.orderedItems ?? [])
          .filter((item) => item.dishId)
          .map((item) => {
            names.set(item.dishId.toString(), item.name);
            return item.dishId.toString();
          })
      ),
    ];

    for (const id of ids) {
      itemCounts.set(id, (itemCounts.get(id) ?? 0) + 1);
    }

    // Every unordered pair on the ticket.
    for (let i = 0; i < ids.length; i += 1) {
      for (let j = i + 1; j < ids.length; j += 1) {
        const key = [ids[i], ids[j]].sort().join("|");
        pairCounts.set(key, (pairCounts.get(key) ?? 0) + 1);
      }
    }
  }

  const total = bills.length;

  const pairs = [...pairCounts.entries()]
    .filter(([, count]) => count >= minSupport)
    .map(([key, count]) => {
      const [a, b] = key.split("|");
      const supportA = itemCounts.get(a) ?? 1;
      const supportB = itemCounts.get(b) ?? 1;

      // Lift > 1 means the two appear together more often than chance —
      // the standard association-rule measure.
      const lift =
        (count / total) / ((supportA / total) * (supportB / total));

      return {
        a: { dishId: a, name: names.get(a) },
        b: { dishId: b, name: names.get(b) },
        together: count,
        // Confidence in each direction: given A, how often does B appear.
        confidenceAtoB: Math.round((count / supportA) * 100),
        confidenceBtoA: Math.round((count / supportB) * 100),
        lift: round2(lift),
      };
    })
    .filter((pair) => pair.lift > 1.1)
    .sort((a, b) => b.lift - a.lift)
    .slice(0, 25);

  return { ready: true, billsAnalysed: total, pairs };
};

/**
 * Upsell suggestions for a cart in progress, for the QR menu.
 *
 * Returns the dishes most often bought alongside what's already selected,
 * ranked by how strongly they associate.
 */
export const suggestUpsells = async (hotelId, dishIds = [], limit = 3) => {
  if (dishIds.length === 0) return [];

  const { ready, pairs } = await analyseBaskets(hotelId, { minSupport: 2 });
  if (!ready) return [];

  const selected = new Set(dishIds.map(String));
  const scores = new Map();

  for (const pair of pairs) {
    const [inCart, candidate] = selected.has(pair.a.dishId)
      ? [pair.a, pair.b]
      : selected.has(pair.b.dishId)
        ? [pair.b, pair.a]
        : [null, null];

    if (!inCart || selected.has(candidate.dishId)) continue;

    const score = pair.lift * (pair.together / 10);
    const existing = scores.get(candidate.dishId);
    if (!existing || existing.score < score) {
      scores.set(candidate.dishId, {
        dishId: candidate.dishId,
        name: candidate.name,
        score,
        because: inCart.name,
      });
    }
  }

  const ranked = [...scores.values()]
    .sort((a, b) => b.score - a.score)
    .slice(0, limit);

  const dishes = await Dish.find({
    _id: { $in: ranked.map((r) => r.dishId) },
    hotelId: oid(hotelId),
    isDeleted: false,
    // Never suggest something the kitchen can't make.
    outOfStock: false,
  }).select("name price logo description");

  const dishById = new Map(dishes.map((d) => [d._id.toString(), d]));

  return ranked
    .filter((entry) => dishById.has(entry.dishId))
    .map((entry) => ({
      dish: dishById.get(entry.dishId),
      reason: `Often ordered with ${entry.because}`,
    }));
};

/* ── Anomaly detection ────────────────────────────────────────────────────
   Flags days that fall well outside the norm *for that day of the week*.

   Comparing against a single overall mean does not work for a restaurant:
   Saturday routinely takes twice what Monday does, so ordinary weekly rhythm
   inflates the standard deviation and hides the days that actually matter —
   a quiet Saturday reads as normal, a busy Monday as an outlier. Scoring each
   day against its own weekday's baseline removes that seasonality. */

export const detectAnomalies = async (hotelId, { lookbackDays = 90 } = {}) => {
  const hotelObjectId = oid(hotelId);
  const since = new Date(Date.now() - lookbackDays * 24 * 60 * 60 * 1000);

  const daily = await Bill.aggregate([
    {
      $match: {
        hotelId: hotelObjectId,
        status: BILL_STATUS.PAID,
        createdAt: { $gte: since },
      },
    },
    {
      $group: {
        _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
        weekday: { $first: { $dayOfWeek: "$createdAt" } },
        revenue: { $sum: "$finalAmount" },
        bills: { $sum: 1 },
        discount: { $sum: "$totalDiscount" },
      },
    },
    { $sort: { _id: 1 } },
  ]);

  if (daily.length < 21) {
    return {
      ready: false,
      reason: "Needs about three weeks of history to tell a quiet day from an odd one.",
      anomalies: [],
      discountFlags: [],
    };
  }

  // Baseline per weekday.
  const baselines = new Map();
  for (const day of daily) {
    if (!baselines.has(day.weekday)) baselines.set(day.weekday, []);
    baselines.get(day.weekday).push(day.revenue);
  }

  const stats = new Map();
  for (const [weekday, values] of baselines) {
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const sd = Math.sqrt(
      values.reduce((sum, v) => sum + (v - mean) ** 2, 0) / values.length
    );
    stats.set(weekday, { mean, sd, samples: values.length });
  }

  const WEEKDAY_NAMES = [
    "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday",
  ];

  const anomalies = daily
    .map((day) => {
      const base = stats.get(day.weekday);
      // Below three samples there is no baseline worth comparing against.
      if (!base || base.sd === 0 || base.samples < 3) return null;
      return { ...day, z: (day.revenue - base.mean) / base.sd, base };
    })
    .filter((day) => day && Math.abs(day.z) >= 2)
    .map((day) => ({
      date: day._id,
      weekday: WEEKDAY_NAMES[day.weekday - 1],
      revenue: round2(day.revenue),
      bills: day.bills,
      // What a normal one of these days looks like, so the figure has context.
      typicalForWeekday: round2(day.base.mean),
      direction: day.z > 0 ? "above" : "below",
      deviation: `${Math.abs(Math.round((day.revenue / day.base.mean - 1) * 100))}%`,
      note:
        day.z > 0
          ? `Well above a normal ${WEEKDAY_NAMES[day.weekday - 1]} — worth knowing what drove it.`
          : `Well below a normal ${WEEKDAY_NAMES[day.weekday - 1]} — check for a closure, an outage, or unrecorded sales.`,
    }))
    .sort((a, b) => (a.date < b.date ? 1 : -1))
    .slice(0, 10);

  const revenues = daily.map((d) => d.revenue);
  const avg = revenues.reduce((a, b) => a + b, 0) / revenues.length;

  // A day where discounts ate an outsized share of revenue is worth a look
  // even when the revenue itself looks normal.
  const discountFlags = daily
    .filter((day) => day.revenue > 0 && day.discount / day.revenue > 0.25)
    .map((day) => ({
      date: day._id,
      revenue: round2(day.revenue),
      discount: round2(day.discount),
      share: `${Math.round((day.discount / day.revenue) * 100)}%`,
      note: "Discounts were a large share of takings that day.",
    }))
    .slice(0, 5);

  return {
    ready: true,
    average: round2(avg),
    anomalies,
    discountFlags,
  };
};
