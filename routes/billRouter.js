import express from 'express';
import { protect, attachHotelId, superAdminOnly, validateOwnership } from '../middlewares/authMiddleware.js';

import { getBill, updateBill, billPaid, getAllBills, deleteBill , sendBillToMail} from '../controllers/billController.js';

const router = express.Router();

router.get('/', protect, attachHotelId, getAllBills);

router.patch('/paid/:billId', protect, validateOwnership, billPaid);

router.post('/send-bill/:billId/:email', protect, validateOwnership, sendBillToMail);

router.get('/:billId', protect, validateOwnership, getBill);

router.delete('/:billId', protect, validateOwnership, deleteBill);

router.put('/:billId', protect, validateOwnership, updateBill);

export default router;
