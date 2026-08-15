import { Dish } from "../models/dishModel.js";
import Offer from "../models/offerModel.js";
import {
  ClientError,
  NotFoundError,
  ValidationError,
} from "../utils/errorHandler.js";

/**
 * Every function here takes `hotelId` and folds it into the query.
 *
 * Previously these looked up by `_id` alone, so any authenticated owner could
 * read, edit or delete another restaurant's menu simply by knowing an id.
 * Scoping in the query — rather than checking after the fetch — means a
 * mismatched tenant is indistinguishable from a missing record.
 */

const assertScope = (hotelId) => {
  if (!hotelId) {
    throw new ClientError(
      "Your account is not linked to a restaurant yet.",
      409,
      "NO_HOTEL_LINKED"
    );
  }
};

const POPULATE = "ingredients category offer";

export const createDishService = async (hotelId, dishData) => {
  assertScope(hotelId);

  if (!dishData.name || dishData.price === undefined) {
    throw new ValidationError("A dish needs a name and a price.");
  }
  if (!dishData.category) {
    throw new ValidationError("Choose a category for this dish.");
  }

  const dish = await Dish.create({ ...dishData, hotelId });
  return dish.populate(POPULATE);
};

export const getDishByIdService = async (dishId, hotelId) => {
  assertScope(hotelId);

  const dish = await Dish.findOne({
    _id: dishId,
    hotelId,
    isDeleted: false,
  }).populate(POPULATE);

  if (!dish) throw new NotFoundError("Dish");
  return dish;
};

/**
 * @param {object} [options]
 * @param {boolean} [options.includeDeleted] Include soft-deleted dishes.
 * @param {string}  [options.search]         Case-insensitive name match.
 * @param {string}  [options.category]       Restrict to one category.
 */
export const getAllDishesService = async (hotelId, options = {}) => {
  assertScope(hotelId);

  const filter = { hotelId };
  if (!options.includeDeleted) filter.isDeleted = false;
  if (options.category) filter.category = options.category;
  if (options.search) {
    // Escaped so a user-supplied string can't act as a regex.
    const escaped = options.search.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    filter.name = { $regex: escaped, $options: "i" };
  }

  return Dish.find(filter).populate(POPULATE).sort({ name: 1 });
};

export const updateDishService = async (dishId, hotelId, dishData) => {
  assertScope(hotelId);

  // hotelId can never be reassigned through an update — that would move a
  // dish between tenants.
  const { hotelId: _ignored, _id: _ignoredId, ...safeData } = dishData;

  if ("category" in safeData && !safeData.category) {
    throw new ValidationError("Choose a category for this dish.");
  }

  const dish = await Dish.findOneAndUpdate({ _id: dishId, hotelId }, safeData, {
    new: true,
    runValidators: true,
  }).populate(POPULATE);

  if (!dish) throw new NotFoundError("Dish");
  return dish;
};

/** Soft delete — history and past bills still reference the dish. */
export const deleteDishService = async (dishId, hotelId) => {
  assertScope(hotelId);

  const dish = await Dish.findOneAndUpdate(
    { _id: dishId, hotelId },
    { isDeleted: true, deletedAt: new Date() },
    { new: true }
  );

  if (!dish) throw new NotFoundError("Dish");
  return dish;
};

/**
 * Filters by `category`, the field the schema actually defines. This queried
 * `categories` — plural, and nonexistent — so it always matched nothing and
 * then threw, meaning browse-by-category never worked.
 */
export const getDishesByCategoryService = async (hotelId, categoryId) => {
  assertScope(hotelId);

  return Dish.find({
    hotelId,
    category: categoryId,
    isDeleted: false,
  })
    .populate(POPULATE)
    .sort({ name: 1 });
};

export const removeOfferFromDishService = async (dishId, hotelId, session) => {
  assertScope(hotelId);

  const dish = await Dish.findOne({ _id: dishId, hotelId }).session(session);
  if (!dish) throw new NotFoundError("Dish");
  if (!dish.offer) {
    throw new ClientError("There is no offer on this dish.", 400, "NO_OFFER");
  }

  const offerId = dish.offer;

  const updatedDish = await Dish.findOneAndUpdate(
    { _id: dishId, hotelId },
    { $set: { offer: null } },
    { new: true, session }
  ).populate(POPULATE);

  await Offer.updateOne(
    { _id: offerId, hotelId },
    { $pull: { appliedOn: dishId } },
    { session }
  );

  return updatedDish;
};

/** Marks a dish in or out of stock without touching anything else. */
export const setDishStockService = async (dishId, hotelId, outOfStock) => {
  assertScope(hotelId);

  const dish = await Dish.findOneAndUpdate(
    { _id: dishId, hotelId },
    { outOfStock: Boolean(outOfStock) },
    { new: true }
  ).populate(POPULATE);

  if (!dish) throw new NotFoundError("Dish");
  return dish;
};
