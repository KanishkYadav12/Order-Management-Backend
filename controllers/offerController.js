import { catchAsyncError } from "../middlewares/catchAsyncError.js";
import {
  createOfferService,
  updateOfferService,
  deleteOfferService,
  getOfferByIdService,
  getAllOffersService,
} from "../services/offerServices.js";

export const getAllOffers = catchAsyncError(async (req, res) => {
  const offers = await getAllOffersService(req.hotelId, {
    type: req.query.type,
    activeOnly: req.query.activeOnly === "true",
  });

  res.status(200).json({
    status: "success",
    message: "Offers loaded",
    data: { offers },
  });
});

export const getOfferDetails = catchAsyncError(async (req, res) => {
  const offer = await getOfferByIdService(req.params.id, req.hotelId);

  res.status(200).json({
    status: "success",
    message: "Offer loaded",
    data: { offer },
  });
});

export const createOffer = catchAsyncError(async (req, res, next, session) => {
  const offer = await createOfferService(req.hotelId, req.body, session);

  res.status(201).json({
    status: "success",
    message: "Offer created",
    data: { offer },
  });
}, true);

export const updateOffer = catchAsyncError(async (req, res, next, session) => {
  const offer = await updateOfferService(
    req.params.id,
    req.hotelId,
    req.body,
    session
  );

  res.status(200).json({
    status: "success",
    message: "Offer updated",
    data: { offer },
  });
}, true);

export const deleteOffer = catchAsyncError(async (req, res, next, session) => {
  const offer = await deleteOfferService(req.params.id, req.hotelId, session);

  res.status(200).json({
    status: "success",
    message: "Offer removed",
    data: { offer },
  });
}, true);
