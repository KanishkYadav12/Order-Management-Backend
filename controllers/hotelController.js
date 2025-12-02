import Hotel from '../models/hotelModel.js';
import { catchAsyncError } from '../middlewares/catchAsyncError.js';
import { getHotelByIdService, updateHotelService, deleteHotelService, getAllHotelsService } from '../services/hotelServices.js';
import { ROLES } from '../utils/constant.js';

// Get hotel by ID (HotelOwner can only access their own hotel, SuperAdmin can access any hotel)
// controllers/hotelController.js


export const getHotelById = catchAsyncError(async (req, res) => {
  console.log("getHotelById called")
  const hotelId = req.user.role === ROLES.HOTEL_OWNER ? req.user.hotelId : req.params.hotelId;

  // Call the service to get hotel details
  const hotel = await getHotelByIdService(req.user, hotelId);

  res.status(200).json({
    status : "success",
    message: 'Hotel details fetched successfully',
    data: { hotel },
  });
});


// Update hotel (SuperAdmin can update any hotel, HotelOwner can update only their own)
export const updateHotel = catchAsyncError(async (req, res) => {
  const hotelId = req.user.role === ROLES.HOTEL_OWNER ? req.user.hotelId : req.params.hotelId;
  const { name, location, logo, description, phone, email } = req.body;

  // Call the service to update the hotel
  const updatedHotel = await updateHotelService(req.user, hotelId, { name, location, logo, description, phone, email });

  res.status(200).json({
    status : "success",
    message: 'Hotel updated successfully',
    data: { hotel: updatedHotel }
  });
});


// Delete hotel (SuperAdmin can delete any hotel, HotelOwner can delete only their own)

export const deleteHotel = catchAsyncError(async (req, res) => {
  const hotelId = req.user.role === ROLES.HOTEL_OWNER ? req.user.hotelId : req.params.hotelId;

  // Call the service to delete the hotel
  await deleteHotelService(req.user, hotelId);

  res.status(200).json({
    status : "success",
    message: 'Hotel deleted successfully',
  });
});


// Get all hotels (SuperAdmin only)
export const getAllHotels = catchAsyncError(async (req, res) => {
  // Call the service to fetch all hotels
  const hotels = await getAllHotelsService(req.user);

  res.status(200).json({
    status : "success",
    message: "All hotels fetched successfully",
    data: { hotels }
  });
});
