import mongoose from "mongoose";
import { Ingredient, Dish } from "../models/dishModel.js";
import {
  ClientError,
  NotFoundError,
  ValidationError,
  ConflictError,
} from "../utils/errorHandler.js";

const assertScope = (hotelId) => {
  if (!hotelId) {
    throw new ClientError(
      "Your account is not linked to a restaurant yet.",
      409,
      "NO_HOTEL_LINKED"
    );
  }
};

export const createIngredientService = async (hotelId, ingredientData) => {
  assertScope(hotelId);
  if (!ingredientData?.name) {
    throw new ValidationError("Give the ingredient a name.");
  }

  try {
    return await Ingredient.create({ ...ingredientData, hotelId });
  } catch (err) {
    if (err.code === 11000) {
      throw new ConflictError("You already have an ingredient with that name.");
    }
    throw err;
  }
};

export const createMultipleIngredientsService = async (hotelId, ingredients) => {
  assertScope(hotelId);
  if (!Array.isArray(ingredients) || ingredients.length === 0) {
    throw new ValidationError("Send at least one ingredient.");
  }

  const documents = ingredients.map((ingredient) => ({ ...ingredient, hotelId }));

  try {
    return await Ingredient.insertMany(documents, { ordered: false });
  } catch (err) {
    if (err.code === 11000 || err.writeErrors) {
      const inserted = err.insertedDocs ?? [];
      if (inserted.length > 0) return inserted;
      throw new ConflictError("Those ingredients already exist.");
    }
    throw err;
  }
};

export const getIngredientByIdService = async (ingredientId, hotelId) => {
  assertScope(hotelId);
  const ingredient = await Ingredient.findOne({
    _id: ingredientId,
    hotelId,
    isDeleted: false,
  });
  if (!ingredient) throw new NotFoundError("Ingredient");
  return ingredient;
};

export const updateIngredientService = async (ingredientId, hotelId, data) => {
  assertScope(hotelId);
  const { hotelId: _ignored, _id: _ignoredId, ...safeData } = data;

  try {
    const ingredient = await Ingredient.findOneAndUpdate(
      { _id: ingredientId, hotelId },
      safeData,
      { new: true, runValidators: true }
    );
    if (!ingredient) throw new NotFoundError("Ingredient");
    return ingredient;
  } catch (err) {
    if (err.code === 11000) {
      throw new ConflictError("You already have an ingredient with that name.");
    }
    throw err;
  }
};

/**
 * Soft-deletes an ingredient, refusing while dishes still list it — a hard
 * delete left dangling references on every dish that used it.
 */
export const deleteIngredientService = async (ingredientId, hotelId) => {
  assertScope(hotelId);

  if (!mongoose.isValidObjectId(ingredientId)) {
    throw new ClientError("That ingredient id is not valid.", 400);
  }

  const inUse = await Dish.countDocuments({
    hotelId,
    isDeleted: false,
    $or: [
      { ingredients: ingredientId },
      { "recipe.ingredientId": ingredientId },
    ],
  });

  if (inUse > 0) {
    throw new ClientError(
      `This ingredient is used by ${inUse} dish${inUse === 1 ? "" : "es"}. Remove it from them first.`,
      409,
      "INGREDIENT_IN_USE"
    );
  }

  const ingredient = await Ingredient.findOneAndUpdate(
    { _id: ingredientId, hotelId },
    { isDeleted: true },
    { new: true }
  );
  if (!ingredient) throw new NotFoundError("Ingredient");
  return ingredient;
};

export const getIngredientsByHotelService = async (hotelId, options = {}) => {
  assertScope(hotelId);

  const filter = { hotelId };
  if (!options.includeDeleted) filter.isDeleted = false;

  return Ingredient.find(filter).sort({ name: 1 });
};

/** Tracked ingredients at or below their low-stock threshold. */
export const getLowStockIngredientsService = async (hotelId) => {
  assertScope(hotelId);

  return Ingredient.find({
    hotelId,
    isDeleted: false,
    stockQuantity: { $ne: null },
    lowStockThreshold: { $ne: null },
    $expr: { $lte: ["$stockQuantity", "$lowStockThreshold"] },
  }).sort({ name: 1 });
};

/** Adjusts stock by a signed delta. Negative values consume. */
export const adjustIngredientStockService = async (
  ingredientId,
  hotelId,
  delta,
  session
) => {
  assertScope(hotelId);

  const ingredient = await Ingredient.findOneAndUpdate(
    { _id: ingredientId, hotelId, stockQuantity: { $ne: null } },
    // Never let tracked stock go negative through an adjustment.
    [
      {
        $set: {
          stockQuantity: {
            $max: [0, { $add: ["$stockQuantity", delta] }],
          },
        },
      },
    ],
    { new: true, session }
  );

  return ingredient;
};

/**
 * Copies one hotel's ingredient list into another. Super-admin only.
 *
 * The previous implementation spread `ingredient._doc`, carrying `_id` and
 * timestamps across, so `insertMany` failed on duplicate keys the moment the
 * destination already had anything.
 */
export const syncIngredientsFromSourceToDestinationService = async (
  sourceHotelId,
  destinationHotelId
) => {
  if (!sourceHotelId || !destinationHotelId) {
    throw new ValidationError("Both a source and a destination are required.");
  }
  if (String(sourceHotelId) === String(destinationHotelId)) {
    throw new ValidationError("Source and destination must be different.");
  }

  const source = await Ingredient.find({
    hotelId: sourceHotelId,
    isDeleted: false,
  }).lean();

  if (source.length === 0) {
    throw new NotFoundError("Ingredients for the source restaurant");
  }

  const existing = new Set(
    await Ingredient.distinct("name", { hotelId: destinationHotelId })
  );

  const documents = source
    .filter((ingredient) => !existing.has(ingredient.name))
    .map(({ name, logo, description, unit, lowStockThreshold, costPerUnit }) => ({
      name,
      logo,
      description,
      unit,
      lowStockThreshold,
      costPerUnit,
      hotelId: destinationHotelId,
    }));

  if (documents.length === 0) return [];

  return Ingredient.insertMany(documents, { ordered: false });
};
