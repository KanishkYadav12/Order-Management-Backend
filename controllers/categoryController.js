import {createCategoryService,createMultipleCategoriesService,getCategoryByIdService ,getAllCategoriesService,deleteCategoryService,updateCategoryService,deleteMultipleCategoriesService} from '../services/categoryServices.js';
import { catchAsyncError } from '../middlewares/catchAsyncError.js';

export const createCategory = catchAsyncError(async (req, res) => {
    const categoryData = req.body;
    const category = await createCategoryService(req.user.hotelId, categoryData);
    res.status(201).json({
        status : "success",
        message: 'Category created successfully',
        data: { category },
    });
});

export const createMultipleCategories = catchAsyncError(async (req, res) => {
    const {categories} = req.body;
    const createdCategories = await createMultipleCategoriesService(req.user.hotelId, categories);
    res.status(201).json({
        status : "success",
        message: 'Categories created successfully',
        data: { categories: createdCategories },
    });
});

export const getCategoryById = catchAsyncError(async (req, res) => {
    const categoryId = req.params.categoryId;
    const category = await getCategoryByIdService(categoryId);
    res.status(200).json({
        status : "success",
        message: 'Category fetched successfully',
        data: { category },
    });
});

export const getAllCategories = catchAsyncError(async (req, res) => {
    const categories = await getAllCategoriesService(req.user.hotelId);
    res.status(200).json({
        status : "success",
        message: 'All categories fetched successfully',
        data: { categories },
    });
});

export const updateCategory = catchAsyncError(async (req, res) => {
    const categoryId = req.params.categoryId;
    const categoryData = req.body;
    const category = await updateCategoryService(categoryId, categoryData);
    res.status(200).json({
        status : "success",
        message: 'Category updated successfully',
        data: { category },
    });
});

export const deleteCategory = catchAsyncError(async (req, res) => {
    const categoryId = req.params.categoryId;
    const category = await deleteCategoryService(categoryId);
    res.status(200).json({
        status : "success",
        message: 'Category deleted successfully',
        data : {category : category}
    });
});

export const deleteMultipleCategories = catchAsyncError(async (req, res) => {
    const { categoryIds } = req.body;
    await deleteMultipleCategoriesService(categoryIds);
    res.status(200).json({
        status : "success",
        message: 'Categories deleted successfully',
    });
});

