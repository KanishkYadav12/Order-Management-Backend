import express from 'express';
import { protect, attachHotelId, superAdminOnly } from '../middlewares/authMiddleware.js';
import uploadStream from '../utils/memoryStorage.js';
import { createDish, getAllDishes, getDishById, getDishesByCategory, updateDish, deleteDish, removeOfferFromDish } from '../controllers/dishController.js';

const router = express.Router();

router.get('/', protect, attachHotelId, getAllDishes);

router.post('/', protect, attachHotelId, createDish);

router.get('/category/:categoryId', protect, attachHotelId, getDishesByCategory);

router.get('/:dishId', protect, attachHotelId, getDishById);

router.patch('/:dishId', protect, attachHotelId, updateDish);

router.delete('/:dishId', protect, attachHotelId, deleteDish);

router.put('/remove-offer/:dishId', protect, attachHotelId, removeOfferFromDish)

export default router;
