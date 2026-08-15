import { catchAsyncError } from "../middlewares/catchAsyncError.js";
import {
  getHotelByIdService,
  updateHotelService,
  deleteHotelService,
  getAllHotelsService,
} from "../services/hotelServices.js";

export const getHotelById = catchAsyncError(async (req, res) => {
  const hotel = await getHotelByIdService(req.user, req.params.hotelId);

  res.status(200).json({
    status: "success",
    message: "Restaurant loaded",
    data: { hotel },
  });
});

/** The signed-in user's own restaurant, without needing to know its id. */
export const getMyHotel = catchAsyncError(async (req, res) => {
  const hotel = await getHotelByIdService(req.user, req.user.hotelId);

  res.status(200).json({
    status: "success",
    message: "Restaurant loaded",
    data: { hotel },
  });
});

export const updateHotel = catchAsyncError(async (req, res) => {
  const hotel = await updateHotelService(
    req.user,
    req.params.hotelId,
    req.body
  );

  res.status(200).json({
    status: "success",
    message: "Restaurant updated",
    data: { hotel },
  });
});

export const deleteHotel = catchAsyncError(async (req, res) => {
  const hotel = await deleteHotelService(req.user, req.params.hotelId);

  res.status(200).json({
    status: "success",
    message: "Restaurant deactivated",
    data: { hotel },
  });
});

export const getAllHotels = catchAsyncError(async (req, res) => {
  const { hotels, pagination } = await getAllHotelsService(req.query);

  res.status(200).json({
    status: "success",
    message: "Restaurants loaded",
    data: { hotels, pagination },
  });
});
