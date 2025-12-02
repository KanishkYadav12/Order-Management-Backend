import { Dish } from "../models/dishModel.js";
import Offer from "../models/offerModel.js";

import { ClientError, ServerError } from "../utils/errorHandler.js";

export const createDishService = async (dishData) => {
    try {
        const hotelId = dishData.hotelId;
        if (!hotelId) {
            throw new ClientError("Hotel ID is required");
        }
        console.log('dish-data-1', dishData)
        if (!dishData.name || !dishData.price) {
            throw new ClientError("Dish name and price are required!");
        }
        if(!dishData.category || dishData.category == null || dishData.category == "" ){
            throw new ClientError("Category is required to create dish!");
        }
        console.log('dish-data-2', dishData, typeof dishData.price)

        const dish = await Dish.create({ ...dishData, hotelId });

        return dish;
    } catch (error) {
        console.log("error while creating dish", error);
        throw error;
    }
}

export const getDishByIdService = async (dishId) => {
    try {
        const dish = await Dish.findById(dishId).populate("ingredients category offer");
        if (!dish) {
            throw new ClientError('Dish not found');
        }
        return dish;
    }
    catch (error) {
        console.log("fetch-all-dish", error)
        if (error instanceof ClientError) {
            throw new error;
        } else {
            throw new ServerError('Failed to fetch dish');
        }
    }
}

export const getAllDishesService = async (hotelId) => {
    try {
        // const dishes = await Dish.find({ hotelId }).populate("ingredients category offer");

        const dishes = await Dish.find({ hotelId, isDeleted: false }).populate("ingredients category offer");

        // if (!dishes || dishes.length === 0) {
        //     throw new ClientError("No dishes available!", "Not found");
        // }

        return dishes;
    } catch (error) {
        if(error instanceof ClientError){
            throw error;
        }
        throw new ServerError('Failed to fetch dishes');
    }
}

export const updateDishService = async (dishId, dishData) => {
    try {
        console.log("dish data : ", dishData)
        if(!dishData.category || dishData.category == null || dishData.category == "" ){
            throw new ServerError("Category is required to create dish!");
        }
        const dish = await Dish.findByIdAndUpdate(dishId, dishData, { new: true, runValidators: true }).populate("ingredients category offer");

        if (!dish) {
            throw new ClientError('Dish not found');
        }
        return dish;
    }
    catch (error) {
        console.log("update dish err : ", error)
        throw new ServerError(error.message || 'Failed to update dish');
    }

}

export const deleteDishService = async (dishId) => {
    try {
        //find the dish by id and set isDeleted to true
        const dish = await Dish.findByIdAndUpdate(dishId, { isDeleted: true }, { new: true });
        if (!dish) {
            throw new ClientError('Dish not found');
        }
        return dish;
    } catch (error) {
        if (error instanceof ClientError) {
            throw new ClientError(error.message);
        } else {
            throw new ServerError('Failed to delete dish');
        }
    }
}

export const getDishesByCategoryService = async (hotelId, categoryId) => {
    try {
        const dishes = await Dish.find({
            hotelId,
            categories: categoryId,
            isDeleted: false,
        });

        if (!dishes || dishes.length === 0) {
            throw new ClientError("NotFoundError", "No dishes found");
        }

        return dishes;
    } catch (error) {
        throw new ServerError('Failed to fetch dishes');
    }
};

export const removeOfferFromDishService = async (dishId, session) => {
    // Fetch the dish to get the offer
    try {
        const dish = await Dish.findById(dishId);

        if (!dish) {
            throw new ClientError('Dish not found!');
        }

        if (!dish.offer) {
            throw new ClientError('No offer is applied to this dish!');
        }

        const offerId = dish.offer;

        // Remove the offer from the dish
        const updatedDish = await Dish.findByIdAndUpdate(
            dishId,
            { $unset: { offer: "" } },
            { new: true }
        );

        // Remove the dishId from the offer's appliedOn array
        await Offer.findByIdAndUpdate(
            offerId,
            { $pull: { appliedOn: dishId } },

        );

        return updatedDish;
    } catch (error) {
        console.log("error- while removing offer", error)
        throw error
    }
};

