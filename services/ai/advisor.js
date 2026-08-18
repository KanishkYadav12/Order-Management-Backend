/**
 * The restaurant's own advisor.
 *
 * Three sources of knowledge meet here, and keeping them separate is the whole
 * design:
 *
 *   1. The hotel brief — real figures, computed by `hotelContext.js` from this
 *      restaurant's records. Injected into every turn.
 *   2. The outside world — the date, the festival calendar and live local news
 *      from `worldContext.js`. This is what lets the answer know that today is
 *      a Sawan Monday, or that Independence Day was two days ago.
 *   3. Tools — the report catalogue. When a question needs a figure the brief
 *      does not carry, the model asks for it and *the server* runs the query.
 *
 * The model supplies judgement and world knowledge. It never supplies a number
 * about this restaurant. That single rule is what makes a free-tier model safe
 * to put in front of an owner who is about to spend money on the advice.
 */
import { chatWithTools, isEnabled } from "./llmProvider.js";
import { buildHotelBrief } from "./hotelContext.js";
import { worldContext, calendarContext } from "./worldContext.js";
import {
  analyseMenu,
  forecastDemand,
  forecastPrep,
  analyseBaskets,
  detectAnomalies,
} from "./menuIntelligence.js";
import { getDashboardStatsService } from "../dashboardServices.js";
import logger from "../../utils/logger.js";

/* ── Tools ────────────────────────────────────────────────────────────── */

/**
 * Everything the model may ask the server to compute.
 *
 * Descriptions are written for the model, not for a developer — they are the
 * only thing it has to choose between them.
 */
const TOOLS = {
  getMenuPerformance: {
    declaration: {
      name: "getMenuPerformance",
      description:
        "Per-dish profitability and popularity for this restaurant. Classes every dish as a star (popular and profitable), plowhorse (popular, low margin), puzzle (profitable, unpopular) or dog (neither). Use for questions about which dishes to promote, reprice, or remove.",
      parameters: {
        type: "OBJECT",
        properties: {
          days: { type: "NUMBER", description: "How many days back to analyse. Default 30." },
        },
      },
    },
    run: (hotelId, args) => analyseMenu(hotelId, { days: args.days ?? 30 }),
  },

  getForecast: {
    declaration: {
      name: "getForecast",
      description:
        "Expected covers and revenue for the coming days, based on this restaurant's own history by day of week. Use when asked about tomorrow, the weekend, or what to expect.",
      parameters: {
        type: "OBJECT",
        properties: {
          days: { type: "NUMBER", description: "How many days ahead. Default 7." },
        },
      },
    },
    run: (hotelId, args) => forecastDemand(hotelId, { days: args.days ?? 7 }),
  },

  getPrepPlan: {
    declaration: {
      name: "getPrepPlan",
      description:
        "How many portions of each dish to prepare for an upcoming day. Use for kitchen planning and stock questions.",
      parameters: {
        type: "OBJECT",
        properties: {
          date: { type: "STRING", description: "Target date as YYYY-MM-DD." },
        },
      },
    },
    run: (hotelId, args) => forecastPrep(hotelId, args.date ? { date: args.date } : {}),
  },

  getDishPairings: {
    declaration: {
      name: "getDishPairings",
      description:
        "Which dishes this restaurant's diners order together, with lift. Use for combo, upsell and meal-deal questions.",
      parameters: { type: "OBJECT", properties: {} },
    },
    run: (hotelId) => analyseBaskets(hotelId, {}),
  },

  getUnusualDays: {
    declaration: {
      name: "getUnusualDays",
      description:
        "Days whose takings fell well outside the normal range for that weekday. Use when asked why business dipped or spiked.",
      parameters: { type: "OBJECT", properties: {} },
    },
    run: (hotelId) => detectAnomalies(hotelId, {}),
  },

  getSalesForPeriod: {
    declaration: {
      name: "getSalesForPeriod",
      description:
        "Revenue, covers, average bill, payment mix and top dishes for an explicit date range. Use when the question names a period the standing brief does not already cover.",
      parameters: {
        type: "OBJECT",
        properties: {
          from: { type: "STRING", description: "Start date, YYYY-MM-DD." },
          to: { type: "STRING", description: "End date, YYYY-MM-DD." },
        },
        required: ["from", "to"],
      },
    },
    run: (hotelId, args) =>
      getDashboardStatsService(hotelId, { from: args.from, to: args.to }),
  },
};

const DECLARATIONS = Object.values(TOOLS).map((tool) => tool.declaration);

/* ── Prompt ───────────────────────────────────────────────────────────── */

const SYSTEM = `You are the personal business advisor to the owner of a single
restaurant. You know this restaurant intimately — its menu, its numbers, its
busy nights — and you also know the world outside it: the calendar, festivals,
local news, and how restaurants work in general.

Your job is to help the owner make money and make decisions. Be the advisor a
good operator would pay for.

## The one hard rule
Never invent a figure about this restaurant. Every number you state about their
sales, dishes, tables or stock must come from the BRIEF below or from a tool
you called. If you do not have a number, say so and call a tool, or say what
you would need. Inventing "revenue was around ₹4 lakh" is the single worst
thing you can do here.

You are free — encouraged — to use your own knowledge of the world: what people
eat during Shravan, how restaurants decorate for Diwali, why a Saturday behaves
differently from a Tuesday, what a combo should cost. That is judgement, not
data, and it is what you are for.

## How to answer
- Lead with the answer. One sentence. Then the reasoning.
- Be specific to THIS restaurant. "Push your Paneer Tikka" beats "push a
  starter". Name their dishes, their days, their numbers.
- When you recommend something, say what it should earn or save, and why you
  think so.
- Amounts are Indian rupees: ₹1,240, or ₹1.2L above a lakh. No decimals unless
  under ₹100.
- Short paragraphs. Bullets only for genuine lists. No preamble, no restating
  the question, no "Great question!".
- If the news or calendar gives you something genuinely useful, use it. If it
  does not, ignore it — do not force a festival into an answer about margins.
- You are talking to a busy owner, not an analyst. Say "sells a lot but barely
  earns" rather than "plowhorse quadrant".`;

const buildSystemPrompt = (brief, world) => `${SYSTEM}

## BRIEF — ${brief.restaurant.name}
Every figure here is real, computed from their records just now.

${JSON.stringify(brief, null, 1)}

## TODAY AND THE CALENDAR
${JSON.stringify(world.calendar, null, 1)}

## LOCAL NEWS AND EVENTS
Headlines near ${world.news.place}, fetched live. Use them when relevant to a
restaurant; ignore them when not.

${JSON.stringify(
  {
    local: world.news.local.map((item) => item.headline),
    dining: world.news.dining.map((item) => item.headline),
    india: world.news.events.map((item) => item.headline),
  },
  null,
  1
)}`;

/* ── The conversation ─────────────────────────────────────────────────── */

const MAX_TOOL_ROUNDS = 3;

/**
 * Answers one message in an ongoing conversation.
 *
 * @param {string} hotelId
 * @param {string} message      What the owner just asked.
 * @param {Array}  history      Prior turns as [{role: "user"|"model", text}].
 * @returns {{reply: string, toolsUsed: string[], groundedOn: object}}
 */
export const advise = async (hotelId, message, history = []) => {
  if (!isEnabled()) {
    return {
      reply:
        "The assistant is not switched on yet. Add a free Gemini API key as AI_API_KEY and set AI_PROVIDER=gemini, and I'll be able to answer properly. The reports under Insights work without it.",
      toolsUsed: [],
      groundedOn: null,
    };
  }

  // The brief comes first because the news feed is scoped to the restaurant's
  // own city, which only the brief knows.
  const brief = await buildHotelBrief(hotelId);

  // Enrichment, never a dependency: a slow or dead feed must not cost the
  // owner their answer, so this degrades to calendar-only.
  const located = await worldContext({
    location: brief.restaurant.location,
  }).catch(() => ({
    calendar: calendarContext(),
    news: { place: "India", local: [], dining: [], events: [] },
  }));

  const system = buildSystemPrompt(brief, located);

  const messages = [
    ...history.slice(-10).map((turn) => ({
      role: turn.role === "model" ? "model" : "user",
      parts: [{ text: turn.text }],
    })),
    { role: "user", parts: [{ text: message }] },
  ];

  const toolsUsed = [];

  for (let round = 0; round <= MAX_TOOL_ROUNDS; round += 1) {
    const result = await chatWithTools({
      system,
      messages,
      // Withhold the tools on the final round so the model must answer with
      // what it has rather than looping forever.
      tools: round < MAX_TOOL_ROUNDS ? DECLARATIONS : [],
    });

    if (result.toolCalls.length === 0) {
      return {
        reply: result.text || "I couldn't put an answer together for that one.",
        toolsUsed,
        groundedOn: {
          restaurant: brief.restaurant.name,
          calendar: located.calendar,
          newsCount:
            located.news.local.length +
            located.news.dining.length +
            located.news.events.length,
        },
      };
    }

    // Echo the model's own turn back verbatim; Gemini 3 rejects the follow-up
    // if the thought signature it returned is missing.
    messages.push(result.raw ?? {
      role: "model",
      parts: result.toolCalls.map((call) => ({
        functionCall: { name: call.name, args: call.args },
      })),
    });

    const responses = await Promise.all(
      result.toolCalls.map(async (call) => {
        const tool = TOOLS[call.name];
        if (!tool) {
          return { name: call.name, response: { error: "No such tool." } };
        }

        toolsUsed.push(call.name);
        try {
          const data = await tool.run(hotelId, call.args ?? {});
          return { name: call.name, response: { data } };
        } catch (err) {
          logger.warn({ err: err.message, tool: call.name }, "advisor tool failed");
          return {
            name: call.name,
            response: { error: "That report could not be produced right now." },
          };
        }
      })
    );

    messages.push({
      role: "user",
      parts: responses.map((entry) => ({
        functionResponse: { name: entry.name, response: entry.response },
      })),
    });
  }

  return {
    reply:
      "I gathered the reports but couldn't finish the answer. Try asking about one thing at a time.",
    toolsUsed,
    groundedOn: null,
  };
};

export { TOOLS, DECLARATIONS };
export default advise;
