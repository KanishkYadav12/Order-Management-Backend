import { Category, Dish } from "../models/dishModel.js";
import {
  ClientError,
  NotFoundError,
  ValidationError,
  ConflictError,
} from "../utils/errorHandler.js";

/** Every query is scoped to one restaurant — see dishServices for the rationale. */
const assertScope = (hotelId) => {
  if (!hotelId) {
    throw new ClientError(
      "Your account is not linked to a restaurant yet.",
      409,
      "NO_HOTEL_LINKED"
    );
  }
};

export const createCategoryService = async (hotelId, categoryData) => {
  assertScope(hotelId);
  if (!categoryData?.name) {
    throw new ValidationError("Give the category a name.");
  }

  try {
    return await Category.create({ ...categoryData, hotelId });
  } catch (err) {
    if (err.code === 11000) {
      throw new ConflictError("You already have a category with that name.");
    }
    throw err;
  }
};

export const createMultipleCategoriesService = async (hotelId, categories) => {
  assertScope(hotelId);
  if (!Array.isArray(categories) || categories.length === 0) {
    throw new ValidationError("Send at least one category.");
  }

  const documents = categories.map((category) => ({ ...category, hotelId }));

  try {
    // `ordered: false` so one duplicate does not discard the whole batch.
    return await Category.insertMany(documents, { ordered: false });
  } catch (err) {
    if (err.code === 11000 || err.writeErrors) {
      const inserted = err.insertedDocs ?? [];
      if (inserted.length > 0) return inserted;
      throw new ConflictError("Those categories already exist.");
    }
    throw err;
  }
};

export const getCategoryByIdService = async (categoryId, hotelId) => {
  assertScope(hotelId);
  const category = await Category.findOne({
    _id: categoryId,
    hotelId,
    isDeleted: false,
  });
  if (!category) throw new NotFoundError("Category");
  return category;
};

export const getAllCategoriesService = async (hotelId) => {
  assertScope(hotelId);
  return Category.find({ hotelId, isDeleted: false }).sort({
    displayOrder: 1,
    name: 1,
  });
};

export const updateCategoryService = async (categoryId, hotelId, data) => {
  assertScope(hotelId);
  const { hotelId: _ignored, _id: _ignoredId, ...safeData } = data;

  try {
    const category = await Category.findOneAndUpdate(
      { _id: categoryId, hotelId },
      safeData,
      { new: true, runValidators: true }
    );
    if (!category) throw new NotFoundError("Category");
    return category;
  } catch (err) {
    if (err.code === 11000) {
      throw new ConflictError("You already have a category with that name.");
    }
    throw err;
  }
};

/**
 * Soft-deletes a category.
 *
 * Refuses while dishes still reference it — silently orphaning menu items is
 * how a restaurant ends up with dishes that never appear on the customer menu.
 */
export const deleteCategoryService = async (categoryId, hotelId) => {
  assertScope(hotelId);

  const dishCount = await Dish.countDocuments({
    hotelId,
    category: categoryId,
    isDeleted: false,
  });

  if (dishCount > 0) {
    throw new ClientError(
      `Move or remove the ${dishCount} dish${dishCount === 1 ? "" : "es"} in this category first.`,
      409,
      "CATEGORY_IN_USE"
    );
  }

  const category = await Category.findOneAndUpdate(
    { _id: categoryId, hotelId },
    { isDeleted: true },
    { new: true }
  );
  if (!category) throw new NotFoundError("Category");
  return category;
};

export const deleteMultipleCategoriesService = async (categoryIds, hotelId) => {
  assertScope(hotelId);
  if (!Array.isArray(categoryIds) || categoryIds.length === 0) {
    throw new ValidationError("Select at least one category to remove.");
  }

  const inUse = await Dish.distinct("category", {
    hotelId,
    category: { $in: categoryIds },
    isDeleted: false,
  });

  if (inUse.length > 0) {
    throw new ClientError(
      `${inUse.length} of those categories still have dishes in them.`,
      409,
      "CATEGORY_IN_USE"
    );
  }

  const result = await Category.updateMany(
    { _id: { $in: categoryIds }, hotelId },
    { isDeleted: true }
  );
  return { deletedCount: result.modifiedCount };
};
