import express from 'express';
import {
  getUserProfile,
  approveHotelOwner,
  getAllHotelOwners,
  getUnApprovedOwners,
  getApprovedOwners,
  membershipExtender,
  deleteHotelOwner,
  updateOwner,
  sendMailForMembershipExpired
} from '../controllers/userController.js';
import { protect, superAdminOnly } from '../middlewares/authMiddleware.js';
import sendEmail from '../utils/sendEmail.js';


const router = express.Router();

// Protected routes
router.get('/profile', protect, getUserProfile);

router.patch('/owner/:ownerId', protect, updateOwner);

// SuperAdmin-only routes
router.patch('/approve-hotel-owner/:ownerId', protect, superAdminOnly, approveHotelOwner);
router.get('/hotel-owners', protect, superAdminOnly, getAllHotelOwners);
router.delete('/hotel-owner/:ownerId', protect, superAdminOnly, deleteHotelOwner);
router.get('/hotel-owners/pending-approval', protect, superAdminOnly, getUnApprovedOwners);
router.get('/hotel-owners/approved', protect, superAdminOnly, getApprovedOwners);

router.patch('/membership-extender/:hotelOwnerId', protect, superAdminOnly, membershipExtender);

//route to send email to when membership is expired 
router.get('/send-email-membership-expired/:hotelOwnerId',protect,superAdminOnly, sendMailForMembershipExpired);

export default router;
