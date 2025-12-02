import { catchAsyncError } from "../middlewares/catchAsyncError.js";
import {
    createDishService,
    deleteDishService,
    getAllDishesService,
    getDishByIdService,
    updateDishService,
    getDishesByCategoryService,
    removeOfferFromDishService,
} from "../services/dishServices.js";
import { ClientError } from "../utils/errorHandler.js";
import uploadAndGetAvatarUrl from "../utils/uploadAndGetUrl.js";

export const getDishById = catchAsyncError(async (req, res) => {
    const dishId = req.params.dishId;

    // Call the service to get dish details
    const dish = await getDishByIdService(dishId);

    res.status(200).json({
        status: "success",
        message: "Dish details fetched successfully",
        data: { dish },
    });
});

export const getAllDishes = catchAsyncError(async (req, res) => {
    const hotelId = req.user.hotelId;
    console.log('dishes-fetching-request')
    // Call the service to get all dishes
    const dishes = await getAllDishesService(hotelId);

    res.status(200).json({
        status: "success",
        message: "All dishes fetched successfully",
        data: { dishes },
    });
});

export const createDish = catchAsyncError(async (req, res) => {
    const dishData = req.body;
    dishData.hotelId = req.user.hotelId;

    // Call the service to create a new dish
    const dish = await createDishService(dishData);

    res.status(201).json({
        status: "success",
        message: "Dish created successfully",
        data: { dish },
    });
});

export const updateDish = catchAsyncError(async (req, res) => {
    const dishId = req.params.dishId;
    const dishData = req.body;

    // Call the service to update the dish
    const dish = await updateDishService(dishId, dishData);
    // if (req.file) {
    //     const logoUrl = await uploadAndGetAvatarUrl(req.file, 'OMS', dish._id, "stream");
    //     dish.logo = logoUrl;
    //     await dish.save();
    // }

    res.status(200).json({
        status: "success",
        message: "Dish updated successfully",
        data: { dish },
    });
});

export const deleteDish = catchAsyncError(async (req, res) => {
    const dishId = req.params.dishId;

    // Call the service to delete the dish
    const dish = await deleteDishService(dishId);

    res.status(200).json({
        status: "success",
        message: "Dish deleted successfully",
        data: { dish },
    });
});

export const getDishesByCategory = catchAsyncError(async (req, res) => {
    const { categoryId } = req.params;

    // Call the service to get dishes by category
    const dishes = await getDishesByCategoryService(req.user.hotelId, categoryId);

    res.status(200).json({
        status: "success",
        message: "Dishes fetched successfully",
        data: { dishes },
    });
});


export const removeOfferFromDish = catchAsyncError(async (req, res, next, session) => {
    const { dishId } = req.params;
    if (!dishId) {
        throw new ClientError("Please provide dish id to remove offer from dish!")
    }
    const dish = await removeOfferFromDishService(dishId, session);
    console.log("dish in remove offer" ,dish)
    res.status(200).json({
        status: "success",
        message: "Offer removed from dish successfully",
        data: { dish },
    });
}, true)
