import { complete, completeJson, isEnabled } from "./llmProvider.js";
import {
  analyseMenu,
  forecastDemand,
  forecastPrep,
  analyseBaskets,
  detectAnomalies,
} from "./menuIntelligence.js";
import { getDashboardStatsService } from "../dashboardServices.js";
import { ClientError } from "../../utils/errorHandler.js";
import logger from "../../utils/logger.js";

/**
 * The conversational layer.
 *
 * Design rule: **the model never sees the database and never does arithmetic.**
 * It does exactly two jobs — pick which report answers the question, and write
 * the answer in plain language from figures this server computed. Every number
 * in a reply is therefore a real number from a real query, which is what makes
 * a small free-tier model safe to use here.
 *
 * This also keeps the assistant honest when no provider is configured: the
 * reports still work, they just come back as data rather than prose.
 */

/** The reports the assistant is allowed to draw on. */
const REPORTS = {
  dashboard: {
    describe: "Revenue, covers, average ticket, kitchen load and table status.",
    run: (hotelId, params) => getDashboardStatsService(hotelId, params ?? {}),
  },
  menu: {
    describe:
      "Per-dish profitability and popularity, with each dish classed as star, plowhorse, puzzle or dog.",
    run: (hotelId, params) => analyseMenu(hotelId, params ?? {}),
  },
  forecast: {
    describe: "Expected covers and revenue for the coming days.",
    run: (hotelId, params) => forecastDemand(hotelId, params ?? {}),
  },
  prep: {
    describe: "How much of each dish to prepare for a given day.",
    run: (hotelId, params) => forecastPrep(hotelId, params ?? {}),
  },
  pairings: {
    describe: "Which dishes are ordered together, for upselling and combos.",
    run: (hotelId, params) => analyseBaskets(hotelId, params ?? {}),
  },
  anomalies: {
    describe: "Days whose takings fell well outside the normal range.",
    run: (hotelId, params) => detectAnomalies(hotelId, params ?? {}),
  },
};

const SYSTEM = `You are the analyst for a restaurant's management system.

You are given a question and a JSON report that the system has already
computed from the restaurant's own sales records. Answer the question using
only the figures in that report.

Rules:
- Never invent a number. If the report does not contain what was asked, say so
  plainly and name what you would need.
- Lead with the answer in one sentence, then the supporting detail.
- Amounts are Indian rupees; write them as ₹1,240 with no decimals unless the
  figure is under ₹100.
- Be concrete and brief. No preamble, no restating the question, no bullet
  lists unless you are genuinely enumerating items.
- When a report says it is not ready, explain what the restaurant needs to do
  to make it useful — usually "settle a few more bills".
- You are talking to a busy restaurant owner, not an analyst. Skip the jargon:
  say "sells well but earns little" rather than "plowhorse quadrant".`;

/**
 * Chooses which report answers a question.
 *
 * Falls back to a keyword match when no provider is configured, so the
 * assistant degrades to something useful rather than to an error.
 */
const chooseReport = async (question) => {
  const keywordMatch = () => {
    const q = question.toLowerCase();
    if (/(prep|prepare|how much|stock up|tomorrow)/.test(q)) return "prep";
    if (/(forecast|expect|next week|busy|predict|how many.*com)/.test(q)) return "forecast";
    if (/(pair|together|combo|upsell|goes with)/.test(q)) return "pairings";
    if (/(unusual|strange|odd|drop|spike|anomal|wrong)/.test(q)) return "anomalies";
    if (/(dish|menu|profit|margin|remove|price|best.?sell|worst)/.test(q)) return "menu";
    return "dashboard";
  };

  if (!isEnabled()) return { report: keywordMatch(), params: {} };

  try {
    const catalogue = Object.entries(REPORTS)
      .map(([key, value]) => `- ${key}: ${value.describe}`)
      .join("\n");

    const choice = await completeJson({
      system:
        "You route a question to one report. Reply with JSON only: " +
        '{"report": "<name>"}. Choose exactly one name from the list.',
      prompt: `Reports:\n${catalogue}\n\nQuestion: ${question}`,
      maxTokens: 100,
    });

    const report = REPORTS[choice?.report] ? choice.report : keywordMatch();
    return { report, params: {} };
  } catch (err) {
    logger.warn({ err }, "report routing failed; using keyword match");
    return { report: keywordMatch(), params: {} };
  }
};

/**
 * Answers a question about the restaurant.
 *
 * @param {string} hotelId
 * @param {string} question
 * @returns {Promise<{answer: string, report: string, data: object, generated: boolean}>}
 */
export const ask = async (hotelId, question) => {
  const trimmed = String(question ?? "").trim();
  if (trimmed.length < 3) {
    throw new ClientError("Ask a question first.", 400, "EMPTY_QUESTION");
  }
  if (trimmed.length > 500) {
    throw new ClientError("That question is too long.", 400, "QUESTION_TOO_LONG");
  }

  const { report, params } = await chooseReport(trimmed);
  const data = await REPORTS[report].run(hotelId, params);

  if (!isEnabled()) {
    return {
      answer: null,
      report,
      data,
      generated: false,
      note: "Showing the report directly — no AI provider is configured.",
    };
  }

  // The report is trimmed before it goes to the model: free tiers have modest
  // context limits, and the whole report is rarely needed to answer one question.
  const answer = await complete({
    system: SYSTEM,
    prompt: `Question: ${trimmed}\n\nReport (${report}):\n${JSON.stringify(
      data,
      null,
      1
    ).slice(0, 12_000)}`,
    maxTokens: 700,
  });

  return { answer, report, data, generated: true };
};

/**
 * A short written briefing for the dashboard — what changed, what needs
 * attention, what to do about it.
 */
export const dailyBriefing = async (hotelId) => {
  const [stats, menu, forecast, anomalies] = await Promise.all([
    getDashboardStatsService(hotelId, {}),
    analyseMenu(hotelId, {}),
    forecastDemand(hotelId, { days: 3 }),
    detectAnomalies(hotelId, {}),
  ]);

  /** Deterministic headlines — these are correct with or without a model. */
  const highlights = [];

  if (stats.revenue?.today > 0) {
    highlights.push({
      kind: "revenue",
      text: `₹${Math.round(stats.revenue.today).toLocaleString("en-IN")} taken today across ${stats.customers.today} bills.`,
    });
  }
  if (stats.kitchen?.pending > 0) {
    highlights.push({
      kind: "kitchen",
      text: `${stats.kitchen.pending} orders waiting, ${stats.kitchen.preparing} cooking.`,
    });
  }
  if (stats.alerts?.lowStockIngredients > 0) {
    highlights.push({
      kind: "stock",
      text: `${stats.alerts.lowStockIngredients} ingredients are at or below their reorder level.`,
    });
  }
  if (forecast.ready && forecast.busiestDay) {
    highlights.push({
      kind: "forecast",
      text: `${forecast.busiestDay.weekday} looks busiest — around ${forecast.busiestDay.expectedCovers} covers.`,
    });
  }
  if (menu.summary?.dogs > 0) {
    highlights.push({
      kind: "menu",
      text: `${menu.summary.dogs} dishes are selling poorly and earning little.`,
    });
  }
  if (anomalies.ready && anomalies.anomalies.length > 0) {
    const latest = anomalies.anomalies[0];
    highlights.push({
      kind: "anomaly",
      text: `${latest.date} was ${latest.deviation} ${latest.direction} the usual day.`,
    });
  }

  if (!isEnabled()) {
    return { highlights, summary: null, generated: false };
  }

  try {
    const summary = await complete({
      system: SYSTEM,
      prompt:
        "Write a 2-3 sentence morning briefing for the owner from these " +
        "points. Lead with the single most important one. Do not repeat them " +
        "as a list.\n\n" +
        highlights.map((h) => `- ${h.text}`).join("\n"),
      maxTokens: 220,
    });
    return { highlights, summary, generated: true };
  } catch (err) {
    // A briefing is a nicety — never fail the dashboard because the free
    // quota ran out.
    logger.warn({ err }, "briefing generation failed");
    return { highlights, summary: null, generated: false };
  }
};

/** Writes a menu description for a dish, from its own attributes. */
export const describeDish = async ({ name, category, ingredients = [], spiceLevel, isVegetarian }) => {
  if (!isEnabled()) {
    throw new ClientError(
      "Set up an AI provider to generate descriptions.",
      503,
      "AI_UNAVAILABLE"
    );
  }

  return complete({
    system:
      "You write short menu descriptions for an Indian restaurant. One or two " +
      "sentences, 25 words maximum. Appetising but factual — describe what is " +
      "actually in the dish. No exclamation marks, no 'mouth-watering', no " +
      "'culinary journey'.",
    prompt: [
      `Dish: ${name}`,
      category && `Section: ${category}`,
      ingredients.length > 0 && `Made with: ${ingredients.join(", ")}`,
      spiceLevel && spiceLevel !== "none" && `Heat: ${spiceLevel}`,
      isVegetarian != null && (isVegetarian ? "Vegetarian" : "Contains meat or fish"),
    ]
      .filter(Boolean)
      .join("\n"),
    maxTokens: 120,
  });
};

export { REPORTS };
