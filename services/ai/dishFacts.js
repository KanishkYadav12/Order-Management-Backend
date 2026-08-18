/**
 * "What's good about this dish?" — written once, then served from the database.
 *
 * A diner scans the QR code, opens the menu and taps a dish before deciding.
 * The first tap on a given dish generates the write-up; every tap after that
 * reads the stored copy. That matters for three reasons, in this order:
 *
 *   1. Consistency. Two people at the same table must not read two different
 *      descriptions of the same paneer tikka.
 *   2. Speed. Generation takes seconds; a cache read takes milliseconds, and
 *      this sits directly in front of a hungry customer.
 *   3. Cost. The free tier is finite and a busy Saturday is not.
 *
 * The cache is keyed on a fingerprint of what the text was written *from*, so
 * editing a dish's name, price or recipe retires the old copy automatically
 * rather than leaving a description that quietly stops being true.
 */
import { createHash } from "crypto";
import { completeJson, isEnabled, providerInfo } from "./llmProvider.js";
import { Dish } from "../../models/dishModel.js";
import { NotFoundError, ClientError } from "../../utils/errorHandler.js";
import logger from "../../utils/logger.js";

/** Fingerprints the inputs the write-up is derived from. */
const fingerprint = (dish) =>
  createHash("sha1")
    .update(
      JSON.stringify({
        name: dish.name,
        description: dish.description ?? "",
        category: dish.category?.name ?? "",
        ingredients: (dish.ingredients ?? [])
          .map((item) => item?.name ?? String(item))
          .sort(),
      })
    )
    .digest("hex")
    .slice(0, 16);

const SYSTEM = `You write the short "about this dish" panel a diner reads on a
restaurant's QR menu, just before they decide whether to order it.

Write for someone who is hungry and scrolling, not for a nutrition label.

Rules:
- Be appetising and concrete. Name what is actually in it and how it is cooked.
- You may mention genuine, well-established nutritional qualities — "paneer is
  a good source of protein", "rich in fibre". Keep them general and factual.
- NEVER make a medical claim. Nothing cures, treats, prevents, heals or is
  "good for" a named condition. No weight-loss promises. If a dish is heavy,
  it is fine to be honest and call it indulgent.
- Do not invent ingredients that were not given to you.
- No exclamation marks, no "delicious!", no marketing shouting. Confident and
  plain beats excited.

Return JSON exactly like:
{
  "summary": "Two sentences on what it is and why someone would order it.",
  "highlights": ["3 to 4 short phrases, each under 60 characters"],
  "goodToKnow": "One sentence: spice level, how filling, or who it suits.",
  "tags": ["2 to 4 short labels like High protein, Vegetarian, Mild, Sharing"]
}`;

const buildPrompt = (dish) => {
  const ingredients = (dish.ingredients ?? [])
    .map((item) => item?.name)
    .filter(Boolean);

  return `Dish: ${dish.name}
Category: ${dish.category?.name ?? "not specified"}
Price: ₹${dish.price}
${dish.description ? `The restaurant describes it as: ${dish.description}` : ""}
${ingredients.length ? `Ingredients: ${ingredients.join(", ")}` : "Ingredients: not listed"}

Write the panel.`;
};

/** Trims the model's output to the shape and lengths the schema allows. */
const normalise = (raw) => ({
  summary: String(raw?.summary ?? "").trim().slice(0, 400),
  highlights: (Array.isArray(raw?.highlights) ? raw.highlights : [])
    .map((item) => String(item).trim().slice(0, 160))
    .filter(Boolean)
    .slice(0, 5),
  goodToKnow: String(raw?.goodToKnow ?? "").trim().slice(0, 300),
  tags: (Array.isArray(raw?.tags) ? raw.tags : [])
    .map((item) => String(item).trim().slice(0, 40))
    .filter(Boolean)
    .slice(0, 5),
});

/**
 * Returns the stored panel, generating it first if it is missing or stale.
 *
 * @param {object} options
 * @param {boolean} options.force      Regenerate even if a fresh copy exists.
 * @param {boolean} options.autoApprove  Publish immediately. Off by default:
 *   see the note on the schema about who carries the risk of an unreviewed
 *   health claim.
 */
export const getDishFacts = async (
  dishId,
  hotelId,
  { force = false, autoApprove = false } = {}
) => {
  const dish = await Dish.findOne({ _id: dishId, hotelId })
    .populate("category", "name")
    .populate("ingredients", "name");

  if (!dish) throw new NotFoundError("Dish");

  const hash = fingerprint(dish);
  const cached = dish.facts;
  const fresh = cached?.summary && cached.sourceHash === hash;

  if (fresh && !force) {
    return { facts: cached.toObject?.() ?? cached, cached: true, dish };
  }

  if (!isEnabled()) {
    throw new ClientError(
      "Dish write-ups need an AI provider configured.",
      503,
      "AI_UNAVAILABLE"
    );
  }

  const raw = await completeJson({
    system: SYSTEM,
    prompt: buildPrompt(dish),
    /* Generous, because thinking tokens count against this cap on reasoning
       models: too low and the JSON is cut off mid-string rather than the
       model simply writing less. */
    maxTokens: 2500,
  });

  const facts = normalise(raw);
  if (!facts.summary) {
    throw new ClientError(
      "The write-up came back empty. Try again.",
      502,
      "AI_EMPTY_RESPONSE"
    );
  }

  dish.facts = {
    ...facts,
    generatedAt: new Date(),
    model: providerInfo().defaultModel ?? providerInfo().provider,
    sourceHash: hash,
    // A regeneration must not silently keep the previous approval: the text
    // the owner signed off on no longer exists.
    approved: autoApprove,
    approvedAt: autoApprove ? new Date() : undefined,
  };

  await dish.save();

  logger.info({ dishId: String(dish._id), hotelId: String(hotelId) }, "dish facts generated");

  return { facts: dish.facts.toObject?.() ?? dish.facts, cached: false, dish };
};

/** Owner sign-off. Nothing reaches a diner without this. */
export const setDishFactsApproval = async (dishId, hotelId, approved) => {
  const dish = await Dish.findOne({ _id: dishId, hotelId });
  if (!dish) throw new NotFoundError("Dish");

  if (!dish.facts?.summary) {
    throw new ClientError(
      "There is no write-up to publish yet.",
      409,
      "NO_FACTS"
    );
  }

  dish.facts.approved = Boolean(approved);
  dish.facts.approvedAt = approved ? new Date() : undefined;
  await dish.save();

  return dish.facts.toObject?.() ?? dish.facts;
};

/**
 * The diner-facing read.
 *
 * Never generates and never reveals an unapproved draft — this endpoint is
 * reachable by anyone holding a table session, so it must not be a way to burn
 * the restaurant's AI quota or to leak text the owner has not signed off.
 */
export const getPublicDishFacts = async (dishId, hotelId) => {
  const dish = await Dish.findOne({ _id: dishId, hotelId })
    .select("name facts")
    .lean();

  if (!dish) throw new NotFoundError("Dish");
  if (!dish.facts?.approved || !dish.facts.summary) return null;

  const { summary, highlights, goodToKnow, tags } = dish.facts;
  return { dish: dish.name, summary, highlights, goodToKnow, tags };
};

export default getDishFacts;
