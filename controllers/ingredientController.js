import { getIngredientByIdService, syncIngredientsFromSourceToDestinationService, getAllIngredientsService, createIngredientService, deleteIngredientService, getIngredientsByHotelService , updateIngredientService ,createMultipleIngredientsService } from "../services/ingredientServices.js";
import { catchAsyncError } from "../middlewares/catchAsyncError.js";

export const getIngredientById = catchAsyncError(async (req, res) => {
    const ingredientId = req.params.ingredientId;

    // Call the service to get ingredient details
    const ingredient = await getIngredientByIdService(ingredientId);

    res.status(200).json({
        status: "success",
        message: 'Ingredient details fetched successfully',
        data: { ingredient },
    });
});

export const createIngredient = catchAsyncError(async (req, res) => {
    const ingredientData = req.body;
    const ingredient = await createIngredientService(req.user.hotelId, ingredientData);
    res.status(201).json({
        status: "success",
        message: 'Ingredient created successfully',
        data: { ingredient },
    });
});

export const createMultipleIngredients = catchAsyncError(async (req, res) => {

    // Extract ingredients array from the request body
    const { ingredients } = req.body;

    // Check if ingredients array is provided and is valid
    if (!ingredients || !Array.isArray(ingredients) || ingredients.length === 0) {
        throw new ClientError('Ingredients data is required and should be an array', 400);
    }

    // Call the service function to create multiple ingredients, passing the hotelId and ingredients
    const createdIngredients = await createMultipleIngredientsService(req.user.hotelId, ingredients);

    // Send the response with the created ingredients
    res.status(201).json({
        status: 'success',
        message: 'Ingredients created successfully',
        data: { ingredients: createdIngredients },
    });
});
export const updateIngredient = catchAsyncError(async (req, res) => {
    const ingredientId = req.params.ingredientId;
    const ingredientData = req.body;
    const ingredient = await updateIngredientService(ingredientId, ingredientData);
    res.status(200).json({
        status: "success",
        message: 'Ingredient updated successfully',
        data: { ingredient },
    });
});


export const deleteIngredient = catchAsyncError(async (req, res) => {
    const ingredientId = req.params.ingredientId;
    const ingredient = await deleteIngredientService(ingredientId);
    res.status(200).json({
        status: "success",
        message: 'Ingredient deleted successfully',
        data : {ingredient}
    });
});

export const getAllIngredients = catchAsyncError(async (req, res) => {
    // Call the service to fetch all ingredients
    const ingredients = await getAllIngredientsService();
    res.status(200).json({
        status: "success",
        message: 'All ingredients fetched successfully',
        data: { ingredients },
    });
});

export const getIngredientsByHotel = catchAsyncError(async (req, res) => {
    const ingredients = await getIngredientsByHotelService(req.user.hotelId);
    res.status(200).json({
        status: "success",
        message: 'All ingredients of hotel fetched successfully',
        data: { ingredients },
    });
});

export const syncIngredientsFromSourceToDestination = catchAsyncError(async (req, res) => {
    const { source, destination } = req.body;
    await syncIngredientsFromSourceToDestinationService(source, destination);
    res.status(200).json({
        status : "success",
        message: `Ingredients cloned successfully from ${destination} to ${source}`,
    });
});





