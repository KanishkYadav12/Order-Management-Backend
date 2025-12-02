import { attachHotelId, protect, superAdminOnly, validateOwnership } from "../middlewares/authMiddleware.js";
import express from 'express';
import { getTableById, getTables, createTable, updateTable, deleteTable, getOrdersByTable, generateTableBill, getCustomerDetails } from '../controllers/tableController.js';


const router = express.Router();


router.get('/', protect, attachHotelId, getTables);
router.post('/', protect, createTable);
router.get('/bill/:tableId', protect, validateOwnership, generateTableBill);
router.get('/table/:tableId', protect, validateOwnership, getOrdersByTable); 
router.get('/get-customer/:tableId', protect, validateOwnership, getCustomerDetails)


router.get('/:id', protect, getTableById);
router.put('/:tableId', protect, updateTable);

router.delete('/:id', protect, deleteTable);


export default router;