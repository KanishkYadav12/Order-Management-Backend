import { catchAsyncError } from "../middlewares/catchAsyncError.js";
import {
  getIngredientByIdService,
  syncIngredientsFromSourceToDestinationService,
  createIngredientService,
  deleteIngredientService,
  getIngredientsByHotelService,
  getLowStockIngredientsService,
  updateIngredientService,
  createMultipleIngredientsService,
} from "../services/ingredientServices.js";

export const getIngredientById = catchAsyncError(async (req, res) => {
  const ingredient = await getIngredientByIdService(
    req.params.ingredientId,
    req.hotelId
  );

  res.status(200).json({
    status: "success",
    message: "Ingredient loaded",
    data: { ingredient },
  });
});

export const createIngredient = catchAsyncError(async (req, res) => {
  const ingredient = await createIngredientService(req.hotelId, req.body);

  res.status(201).json({
    status: "success",
    message: "Ingredient created",
    data: { ingredient },
  });
});

export const createMultipleIngredients = catchAsyncError(async (req, res) => {
  const ingredients = await createMultipleIngredientsService(
    req.hotelId,
    req.body.ingredients
  );

  res.status(201).json({
    status: "success",
    message: `${ingredients.length} ingredients created`,
    data: { ingredients },
  });
});

export const updateIngredient = catchAsyncError(async (req, res) => {
  const ingredient = await updateIngredientService(
    req.params.ingredientId,
    req.hotelId,
    req.body
  );

  res.status(200).json({
    status: "success",
    message: "Ingredient updated",
    data: { ingredient },
  });
});

export const deleteIngredient = catchAsyncError(async (req, res) => {
  const ingredient = await deleteIngredientService(
    req.params.ingredientId,
    req.hotelId
  );

  res.status(200).json({
    status: "success",
    message: "Ingredient removed",
    data: { ingredient },
  });
});

export const getIngredientsByHotel = catchAsyncError(async (req, res) => {
  const ingredients = await getIngredientsByHotelService(req.hotelId, {
    includeDeleted: req.query.includeDeleted === "true",
  });

  res.status(200).json({
    status: "success",
    message: "Ingredients loaded",
    data: { ingredients },
  });
});

/** Powers the low-stock warning on the dashboard. */
export const getLowStockIngredients = catchAsyncError(async (req, res) => {
  const ingredients = await getLowStockIngredientsService(req.hotelId);

  res.status(200).json({
    status: "success",
    message: "Low stock ingredients loaded",
    data: { ingredients, count: ingredients.length },
  });
});

export const syncIngredientsFromSourceToDestination = catchAsyncError(
  async (req, res) => {
    const { source, destination } = req.body;
    const ingredients = await syncIngredientsFromSourceToDestinationService(
      source,
      destination
    );

    res.status(200).json({
      status: "success",
      message: `${ingredients.length} ingredients copied`,
      data: { ingredients },
    });
  }
);

/** Kept as an alias so any existing import of this name still resolves. */
export const getAllIngredients = getIngredientsByHotel;
