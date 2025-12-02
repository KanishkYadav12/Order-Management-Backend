import e from "express";
import { Category } from "../models/dishModel.js";
import { ClientError, ServerError } from "../utils/errorHandler.js";

export const createCategoryService = async (hotelId, categoryData) => {
    try {

        if (!hotelId) {
            throw new ClientError("Hotel ID is required");
        }

        if (!categoryData.name) {
            throw new ClientError("Category name is required");
        }
        const category = await Category.create({ ...categoryData, hotelId });

        return category;
    } catch (error) {
        if (error instanceof ClientError) {
            throw new error;
        }
        else {
            throw new ServerError("Category creation failed");
        }
    }
}

export const createMultipleCategoriesService = async (hotelId, categoriesData) => {
    try {
        if (!hotelId) {
            throw new ClientError('Hotel ID is required');
        }

        const categories = categoriesData.map(categoryData => ({ ...categoryData, hotelId }));
        const createdCategories = await Category.insertMany(categories);

        return createdCategories;
    } catch (error) {
        if (error instanceof ClientError) {
            throw new error;
        }
        else {
            throw new ServerError('Categories creation failed');
        }
    }
}

export const getCategoryByIdService = async (categoryId) => {
    try {
        const category = await Category.findById(categoryId);
        if (!category) {
            throw new ClientError('Category not found');
        }

        return category;
    }
    catch (error) {
        if (error instanceof ClientError) {
            throw new error;
        } else {
            throw new ServerError('Failed to fetch category');
        }
    }
}

export const getAllCategoriesService = async (hotelId) => {
    try {
        const categories = await Category.find({ hotelId });

        if (!categories || categories.length === 0) {
            return [];
        }

        return categories;
    }
    catch (error) {
        throw error;
    }
}

export const updateCategoryService = async (categoryId, categoryData) => {
    try {
        const category = await Category.findByIdAndUpdate(categoryId, categoryData, { new: true, runValidators: true });
        if (!category) {
            throw new ClientError('Category not found');
        }
        return category;
    }
    catch (error) {
        if (error instanceof ClientError) {
            throw new error;
        } else {
            throw new ServerError('Failed to update category');
        }
    }
}

export const deleteCategoryService = async (categoryId) => {
    try {
        const category = await Category.findByIdAndDelete(categoryId);
        if (!category) {
            throw new ClientError('Category not found');
        }
        return category;
    } catch (error) {
        if (error instanceof ClientError) {
            throw new error;
        } else {
            throw new ServerError('Failed to delete category');
        }
    }
}

export const deleteMultipleCategoriesService = async (categoryIds) => {
    try {
        const categories = await Category.deleteMany({ _id: { $in: categoryIds } });
        if (!categories) {
            throw new ClientError('Categories not found');
        }
    } catch (error) {
        if (error instanceof ClientError) {
            throw new error;
        } else {
            throw new ServerError('Failed to delete categories');
        }
    }
}



