import { attachHotelId, protect, superAdminOnly, validateOwnership } from "../middlewares/authMiddleware.js";
import {
    createOrder,
    onQRScan,
    deleteOrder,
    getOrderDetails,
    publishOrder,
    getAllOrders,
    updateStatus,
    updateOrderByOwner
} from '../controllers/orderController.js';
import express from 'express';

const router = express.Router();

// for customer on scanning QR
router.get('/', protect, attachHotelId, getAllOrders)

router.get('/qr-scan/:tableId', onQRScan);

router.post('/publish/:orderId', publishOrder);

// for customer and hotel owner 
router.post('/:tableId', createOrder);

//for update order by owner
router.put('/owner/:orderId', protect, validateOwnership, updateOrderByOwner);

// for updating order status
router.patch('/:orderId/:status', protect, validateOwnership, updateStatus);

// for hotel owner to fetch order by id
router.get('/details/:orderId', getOrderDetails);

// for hotel owner delete customer order on request
router.delete('/:orderId', protect, validateOwnership, deleteOrder);



export default router;
