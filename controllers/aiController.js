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
