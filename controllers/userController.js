import { catchAsyncError } from '../middlewares/catchAsyncError.js';
import { HotelOwner } from '../models/userModel.js';
import {
  getUserProfileService,
  approveHotelOwnerService,
  getAllHotelOwnersService,
  getUnApprovedOwnersService,
  getApprovedOwnersService,
  membershipExtenderService,
  deleteHotelOwnerService,
  sendMailForMembershipExpiredService,
} from '../services/userServices.js';
import { ClientError } from '../utils/errorHandler.js';

export const getUserProfile = catchAsyncError(async (req, res) => {
  const userId = req.user?.id;
  const user = await getUserProfileService(userId);
  console.log("user------", user)
  res.status(200).json({
    status : "success",
    message: "User profile fetched successfully",
    data: { user },
  });
});

export const updateOwner = catchAsyncError(async (req, res)=> {
  const ownerId = req.user?.id;
  const {name , email , logo , gender, phone} = req.body
  const owner = await HotelOwner.findById(ownerId);
  console.log("owner-------------", owner)
  if(!owner) { throw new ClientError("Owner not found")}
  const updatedOwner = await HotelOwner.findByIdAndUpdate(ownerId, {name, logo, gender, phone, email});
    return res.send({
      status : 'success',
      message : 'owner updated successfully',
      data : {owner :  updatedOwner} 
    })

})

export const approveHotelOwner = catchAsyncError(async (req, res,next,session) => {
  const { ownerId } = req.params;
  const updatedHotelOwner = await approveHotelOwnerService(ownerId, session);

  res.status(200).json({
    status : "success",
    message: `Hotel owner ${updatedHotelOwner.isApproved ? "approved" : "rejected"  } successfully`,
    data: { hotelOwner: updatedHotelOwner}
  });
}, true);

export const getAllHotelOwners = catchAsyncError(async (req, res) => {

  const hotelOwners = await getAllHotelOwnersService();

  res.status(200).json({
    status : "success",
    message: "All hotel owners fetched successfully",
    data: { hotelOwners }
  });
});

export const getUnApprovedOwners = catchAsyncError(async (req, res) => {
  const { page = 1, limit = 10 } = req.query;

  // Call the service to get the pending hotels with pagination data
  const { unApprovedOwners, pagination } = await getUnApprovedOwnersService({ page, limit });

  res.status(200).json({
    status : "success",
    message: "Unapproved owners fetched successfully",
    data: {
      unApprovedOwners,
      pagination,
    },
  });
});

export const getApprovedOwners = catchAsyncError(async (req, res) => {
  const { page = 1, limit = 10 } = req.query;

  // Call the service to get the approved hotel owners with pagination data
  const { approvedOwners, pagination } = await getApprovedOwnersService({ page, limit });

  res.status(200).json({
    status : "success",
    message: "Approved owners fetched successfully",
    data: {
      approvedOwners,
      pagination,
    },
  });
});

export const membershipExtender = catchAsyncError(async (req, res) => {
  // Logic to extend membership
  const hotelOwnerId = req.params.hotelOwnerId;
  // console.log(hotelOwnerId);
  // console.log(req.body);
  
  const {days} = req.body;
  // console.log(days);

  const updatedHotelOwner = await membershipExtenderService(hotelOwnerId, days);

  res.status(200).json({
    status : "success",
    message: "Membership extended successfully",
    data: { updatedHotelOwner }
  });
});

export const deleteHotelOwner = catchAsyncError(async (req, res) => {
  const { ownerId } = req.params;
  await deleteHotelOwnerService(ownerId);
  res.status(200).json({
    status : "success",
    message: 'Hotel owner deleted successfully',
  });
});

export const sendMailForMembershipExpired = catchAsyncError(async (req, res) => { 
      const { hotelOwnerId } = req.params;
      const data = await sendMailForMembershipExpiredService(hotelOwnerId);
      res.status(200).json({
        status : "success",
        message: 'Mail sent successfully',
        data,
      });
});