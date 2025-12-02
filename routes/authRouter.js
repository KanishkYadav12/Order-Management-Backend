import express from 'express';
import { signUp, login, verifyEmail, resendOtp, logout ,forgotPassword, resetPassword} from '../controllers/authController.js';
// import { protect, superAdminOnly } from '../middlewares/authMiddleware.js';

const router = express.Router();

// Public routes
router.post('/signup', signUp);
router.post('/login', login);
router.post('/logout',logout);
router.post('/verify', verifyEmail);
router.post('/resend-otp', resendOtp);
router.post('/forgot-password', forgotPassword);
router.post('/reset-password/:token', resetPassword);

export default router;
