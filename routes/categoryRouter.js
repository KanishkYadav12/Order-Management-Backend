import express from 'express';
import { protect,superAdminOnly,attachHotelId } from '../middlewares/authMiddleware.js';
import { createCategory,createMultipleCategories, deleteCategory,deleteMultipleCategories, getAllCategories, getCategoryById, updateCategory } from '../controllers/categoryController.js';

const router = express.Router();

router.get('/', protect,attachHotelId, getAllCategories);
router.post('/', protect,attachHotelId, createCategory);

router.post('/multiple', protect,attachHotelId, createMultipleCategories);
router.delete('/multiple', protect,attachHotelId, deleteMultipleCategories);

router.get('/:categoryId', protect,attachHotelId, getCategoryById);

router.patch('/:categoryId', protect,attachHotelId, updateCategory);

router.delete('/:categoryId', protect,attachHotelId, deleteCategory);

export default router;

