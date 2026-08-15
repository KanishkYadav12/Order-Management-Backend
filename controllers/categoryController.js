import { catchAsyncError } from "../middlewares/catchAsyncError.js";
import {
  createCategoryService,
  createMultipleCategoriesService,
  getCategoryByIdService,
  getAllCategoriesService,
  deleteCategoryService,
  updateCategoryService,
  deleteMultipleCategoriesService,
} from "../services/categoryServices.js";

export const createCategory = catchAsyncError(async (req, res) => {
  const category = await createCategoryService(req.hotelId, req.body);

  res.status(201).json({
    status: "success",
    message: "Category created",
    data: { category },
  });
});

export const createMultipleCategories = catchAsyncError(async (req, res) => {
  const categories = await createMultipleCategoriesService(
    req.hotelId,
    req.body.categories
  );

  res.status(201).json({
    status: "success",
    message: `${categories.length} categories created`,
    data: { categories },
  });
});

export const getCategoryById = catchAsyncError(async (req, res) => {
  const category = await getCategoryByIdService(
    req.params.categoryId,
    req.hotelId
  );

  res.status(200).json({
    status: "success",
    message: "Category loaded",
    data: { category },
  });
});

export const getAllCategories = catchAsyncError(async (req, res) => {
  const categories = await getAllCategoriesService(req.hotelId);

  res.status(200).json({
    status: "success",
    message: "Categories loaded",
    data: { categories },
  });
});

export const updateCategory = catchAsyncError(async (req, res) => {
  const category = await updateCategoryService(
    req.params.categoryId,
    req.hotelId,
    req.body
  );

  res.status(200).json({
    status: "success",
    message: "Category updated",
    data: { category },
  });
});

export const deleteCategory = catchAsyncError(async (req, res) => {
  const category = await deleteCategoryService(
    req.params.categoryId,
    req.hotelId
  );

  res.status(200).json({
    status: "success",
    message: "Category removed",
    data: { category },
  });
});

export const deleteMultipleCategories = catchAsyncError(async (req, res) => {
  const result = await deleteMultipleCategoriesService(
    req.body.categoryIds,
    req.hotelId
  );

  res.status(200).json({
    status: "success",
    message: `${result.deletedCount} categories removed`,
    data: result,
  });
});
