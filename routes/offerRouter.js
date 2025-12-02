import express from 'express';
import { attachHotelId, protect, superAdminOnly, validateOwnership } from "../middlewares/authMiddleware.js";
import { getOfferDetails, updateOffer, deleteOffer, createOffer, getAllOffers } from "../controllers/offerController.js";


const router = express.Router();

router.get('/:id', protect, validateOwnership, getOfferDetails);

router.get('/', protect, attachHotelId, getAllOffers);

router.post('/', protect, attachHotelId, createOffer);

router.put('/:id', protect, validateOwnership, updateOffer);

router.delete('/:id', protect, validateOwnership, deleteOffer);


export default router;
