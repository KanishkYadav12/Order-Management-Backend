import express from "express";
import { printQr } from "../controllers/qrController.js";
import { protect } from "../middlewares/authMiddleware.js";

const router = express.Router();

router.get('/:tableId', protect, printQr);

// Generate QR code using tableId in params
// router.post('/generate/:tableId', protect, generateQr);

// // Print QR code as PDF using tableId in params
// router.get('/print/:tableId', protect, printQr);

// Generate QR code using tableId in params

export default router;
