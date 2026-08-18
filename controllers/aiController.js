import { catchAsyncError } from "../middlewares/catchAsyncError.js";
import {
  analyseMenu,
  forecastDemand,
  forecastPrep,
  analyseBaskets,
  detectAnomalies,
  suggestUpsells,
} from "../services/ai/menuIntelligence.js";
import { ask, dailyBriefing, describeDish } from "../services/ai/assistant.js";
import { providerInfo } from "../services/ai/llmProvider.js";
import { Dish } from "../models/dishModel.js";
import Conversation from "../models/conversationModel.js";
import { advise } from "../services/ai/advisor.js";
import { NotFoundError } from "../utils/errorHandler.js";
import {
  getDishFacts,
  setDishFactsApproval,
  getPublicDishFacts,
} from "../services/ai/dishFacts.js";

/**
 * Reports the assistant's configuration so the dashboard can show the right
 * state instead of failing a request to find out.
 */
export const getAiStatus = catchAsyncError(async (req, res) => {
  const info = providerInfo();

  res.status(200).json({
    status: "success",
    message: "AI status",
    data: {
      ...info,
      // The analytics never depend on a provider — say so explicitly, so the
      // UI doesn't hide working features behind a "configure AI" prompt.
      analyticsAvailable: true,
    },
  });
});

export const getMenuAnalysis = catchAsyncError(async (req, res) => {
  const analysis = await analyseMenu(req.hotelId, {
    from: req.query.from,
    to: req.query.to,
  });

  res.status(200).json({
    status: "success",
    message: "Menu analysis ready",
    data: analysis,
  });
});

export const getForecast = catchAsyncError(async (req, res) => {
  const forecast = await forecastDemand(req.hotelId, {
    days: Number(req.query.days) || 7,
  });

  res.status(200).json({
    status: "success",
    message: "Forecast ready",
    data: forecast,
  });
});

export const getPrepPlan = catchAsyncError(async (req, res) => {
  const plan = await forecastPrep(req.hotelId, { date: req.query.date });

  res.status(200).json({
    status: "success",
    message: "Prep plan ready",
    data: plan,
  });
});

export const getPairings = catchAsyncError(async (req, res) => {
  const pairings = await analyseBaskets(req.hotelId, {});

  res.status(200).json({
    status: "success",
    message: "Pairings ready",
    data: pairings,
  });
});

export const getAnomalies = catchAsyncError(async (req, res) => {
  const anomalies = await detectAnomalies(req.hotelId, {});

  res.status(200).json({
    status: "success",
    message: "Anomaly scan complete",
    data: anomalies,
  });
});

export const getBriefing = catchAsyncError(async (req, res) => {
  const briefing = await dailyBriefing(req.hotelId);

  res.status(200).json({
    status: "success",
    message: "Briefing ready",
    data: briefing,
  });
});

export const askAssistant = catchAsyncError(async (req, res) => {
  const result = await ask(req.hotelId, req.body.question);

  res.status(200).json({
    status: "success",
    message: "Answered",
    data: result,
  });
});

export const generateDishDescription = catchAsyncError(async (req, res) => {
  const dish = await Dish.findOne({
    _id: req.params.dishId,
    hotelId: req.hotelId,
  }).populate("category ingredients", "name");

  if (!dish) {
    return res
      .status(404)
      .json({ status: "failed", message: "Dish not found", code: "NOT_FOUND" });
  }

  const description = await describeDish({
    name: dish.name,
    category: dish.category?.name,
    ingredients: (dish.ingredients ?? []).map((i) => i.name),
    spiceLevel: dish.spiceLevel,
    isVegetarian: dish.isVegetarian,
  });

  res.status(200).json({
    status: "success",
    message: "Description generated",
    data: { description },
  });
});

/**
 * Upsell suggestions for the QR menu, from what this restaurant's own diners
 * actually order together.
 */
export const getUpsellSuggestions = catchAsyncError(async (req, res) => {
  const { hotelId } = req.params;
  const dishIds = String(req.query.dishes ?? "")
    .split(",")
    .map((id) => id.trim())
    .filter(Boolean);

  const suggestions = await suggestUpsells(hotelId, dishIds, 3);

  res.status(200).json({
    status: "success",
    message: "Suggestions ready",
    data: { suggestions },
  });
});

/* ── The advisor chat ─────────────────────────────────────────────────── */

/**
 * One turn of conversation with the restaurant's advisor.
 *
 * Distinct from `askAssistant`, which is a stateless one-shot over a single
 * report. This carries history, can call several reports in one answer, and
 * knows what day it is and what is happening in the city.
 */
export const chatWithAdvisor = catchAsyncError(async (req, res) => {
  const { message, conversationId } = req.body;

  let conversation = conversationId
    ? await Conversation.findOne({
        _id: conversationId,
        hotelId: req.hotelId,
        userId: req.user._id,
      })
    : null;

  if (!conversation) {
    conversation = new Conversation({
      hotelId: req.hotelId,
      userId: req.user._id,
      // The opening question makes a better title than "New chat".
      title: message.slice(0, 80),
      turns: [],
    });
  }

  const history = conversation.turns.map((turn) => ({
    role: turn.role,
    text: turn.text,
  }));

  const result = await advise(req.hotelId, message, history);

  conversation.turns.push({ role: "user", text: message });
  conversation.turns.push({
    role: "model",
    text: result.reply,
    toolsUsed: result.toolsUsed,
  });
  await conversation.save();

  res.status(200).json({
    status: "success",
    message: "Answered",
    data: {
      conversationId: conversation._id,
      reply: result.reply,
      toolsUsed: result.toolsUsed,
      groundedOn: result.groundedOn,
    },
  });
});

/** The owner's recent conversations, newest first. */
export const listConversations = catchAsyncError(async (req, res) => {
  const conversations = await Conversation.find({
    hotelId: req.hotelId,
    userId: req.user._id,
  })
    .select("title updatedAt turns")
    .sort({ updatedAt: -1 })
    .limit(20)
    .lean();

  res.status(200).json({
    status: "success",
    message: "Conversations loaded",
    data: {
      conversations: conversations.map((item) => ({
        _id: item._id,
        title: item.title,
        updatedAt: item.updatedAt,
        turnCount: item.turns?.length ?? 0,
      })),
    },
  });
});

export const getConversation = catchAsyncError(async (req, res) => {
  const conversation = await Conversation.findOne({
    _id: req.params.conversationId,
    hotelId: req.hotelId,
    userId: req.user._id,
  }).lean();

  if (!conversation) throw new NotFoundError("Conversation");

  res.status(200).json({
    status: "success",
    message: "Conversation loaded",
    data: { conversation },
  });
});

export const deleteConversation = catchAsyncError(async (req, res) => {
  const conversation = await Conversation.findOneAndDelete({
    _id: req.params.conversationId,
    hotelId: req.hotelId,
    userId: req.user._id,
  });

  if (!conversation) throw new NotFoundError("Conversation");

  res.status(200).json({ status: "success", message: "Conversation removed", data: {} });
});

/* ── Dish write-ups for the QR menu ───────────────────────────────────── */

/** Owner-side: generate (or fetch the cached) panel for one dish. */
export const dishFacts = catchAsyncError(async (req, res) => {
  const result = await getDishFacts(req.params.dishId, req.hotelId, {
    force: req.query.force === "true",
  });

  res.status(200).json({
    status: "success",
    message: result.cached ? "Loaded from cache" : "Write-up generated",
    data: { facts: result.facts, cached: result.cached },
  });
});

/** Owner-side: publish or unpublish a write-up. */
export const approveDishFacts = catchAsyncError(async (req, res) => {
  const facts = await setDishFactsApproval(
    req.params.dishId,
    req.hotelId,
    req.body.approved
  );

  res.status(200).json({
    status: "success",
    message: req.body.approved ? "Published to the menu" : "Hidden from the menu",
    data: { facts },
  });
});

/**
 * Diner-side: what the QR menu shows.
 *
 * Reads only. A diner tapping a dish must never trigger generation — that
 * would let anyone with a table session spend the restaurant's AI quota.
 */
export const publicDishFacts = catchAsyncError(async (req, res) => {
  const facts = await getPublicDishFacts(req.params.dishId, req.params.hotelId);

  res.status(200).json({
    status: "success",
    message: facts ? "Loaded" : "Nothing published for this dish",
    data: { facts },
  });
});
