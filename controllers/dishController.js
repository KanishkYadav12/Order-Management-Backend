import { catchAsyncError } from "../middlewares/catchAsyncError.js";
import {
  createDishService,
  deleteDishService,
  getAllDishesService,
  getDishByIdService,
  updateDishService,
  getDishesByCategoryService,
  removeOfferFromDishService,
  setDishStockService,
} from "../services/dishServices.js";

/**
 * `req.hotelId` is set by `attachHotelId`/`requireHotel` and is the only
 * source of tenant scope in this layer — handlers never read a hotel id from
 * the request body.
 */

export const getDishById = catchAsyncError(async (req, res) => {
  const dish = await getDishByIdService(req.params.dishId, req.hotelId);

  res.status(200).json({
    status: "success",
    message: "Dish loaded",
    data: { dish },
  });
});

export const getAllDishes = catchAsyncError(async (req, res) => {
  const dishes = await getAllDishesService(req.hotelId, {
    search: req.query.search,
    category: req.query.category,
    includeDeleted: req.query.includeDeleted === "true",
  });

  res.status(200).json({
    status: "success",
    message: "Dishes loaded",
    data: { dishes },
  });
});

export const createDish = catchAsyncError(async (req, res) => {
  const dish = await createDishService(req.hotelId, req.body);

  res.status(201).json({
    status: "success",
    message: "Dish created",
    data: { dish },
  });
});

export const updateDish = catchAsyncError(async (req, res) => {
  const dish = await updateDishService(
    req.params.dishId,
    req.hotelId,
    req.body
  );

  res.status(200).json({
    status: "success",
    message: "Dish updated",
    data: { dish },
  });
});

export const deleteDish = catchAsyncError(async (req, res) => {
  const dish = await deleteDishService(req.params.dishId, req.hotelId);

  res.status(200).json({
    status: "success",
    message: "Dish removed",
    data: { dish },
  });
});

export const getDishesByCategory = catchAsyncError(async (req, res) => {
  const dishes = await getDishesByCategoryService(
    req.hotelId,
    req.params.categoryId
  );

  res.status(200).json({
    status: "success",
    message: "Dishes loaded",
    data: { dishes },
  });
});

export const removeOfferFromDish = catchAsyncError(
  async (req, res, next, session) => {
    const dish = await removeOfferFromDishService(
      req.params.dishId,
      req.hotelId,
      session
    );

    res.status(200).json({
      status: "success",
      message: "Offer removed from dish",
      data: { dish },
    });
  },
  true
);

/** Quick in/out-of-stock toggle for the floor, without a full dish edit. */
export const setDishStock = catchAsyncError(async (req, res) => {
  const dish = await setDishStockService(
    req.params.dishId,
    req.hotelId,
    req.body.outOfStock
  );

  res.status(200).json({
    status: "success",
    message: dish.outOfStock ? "Dish marked out of stock" : "Dish back in stock",
    data: { dish },
  });
});
