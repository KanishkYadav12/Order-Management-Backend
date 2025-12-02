import express from 'express';
import { getAllIngredients , getIngredientById , createIngredient  , updateIngredient, deleteIngredient, getIngredientsByHotel, syncIngredientsFromSourceToDestination,createMultipleIngredients} from '../controllers/ingredientController.js';
import { attachHotelId, protect,superAdminOnly } from '../middlewares/authMiddleware.js';

const router = express.Router();

router.get('/', protect,attachHotelId, getIngredientsByHotel);
router.post('/',protect,attachHotelId, createIngredient);

router.post('/multiple',protect,attachHotelId, createMultipleIngredients);

// transfer/sync ingredients from source hotel to destination hotel
router.post('/sync',protect, superAdminOnly, syncIngredientsFromSourceToDestination);

router.get('/:ingredientId',protect,attachHotelId, getIngredientById);

router.patch('/:ingredientId',protect,attachHotelId, updateIngredient);

router.delete('/:ingredientId',protect,attachHotelId, deleteIngredient);

export default router;

