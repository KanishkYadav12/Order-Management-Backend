import express from 'express';
import { protect, validateOwnership } from '../middlewares/authMiddleware.js';
import { superAdminOnly } from '../middlewares/authMiddleware.js';
import {
  updateHotel,
  deleteHotel,
  getHotelById,
  getAllHotels
} from '../controllers/hotelController.js';

const router = express.Router();

// Route to get a single hotel by ID (HotelOwner can only view their own hotel, SuperAdmin can view any)
router.get('/:hotelId', protect, getHotelById);

// Route to update a hotel (SuperAdmin can update any hotel, HotelOwner can only update their own)
router.put('/:hotelId', protect , updateHotel); // validate member ship not working here

// Route to delete a hotel (SuperAdmin can delete any hotel, HotelOwner can delete only their own)
router.delete('/:hotelId', protect, validateOwnership, deleteHotel);

// Route to get all hotels (SuperAdmin only)
router.get('/getAllHotels', protect, superAdminOnly, getAllHotels);

export default router;
