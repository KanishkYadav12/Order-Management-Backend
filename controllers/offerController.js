import { catchAsyncError } from "../middlewares/catchAsyncError.js";
import { ClientError } from "../utils/errorHandler.js";
import Offer from "../models/offerModel.js"
import { createOfferService, deleteOfferService, updateOfferService } from "../services/offerServices.js";

export const getOfferDetails = catchAsyncError(async (req, res, next) => {
    const { id } = req.params;
    if (!id) {
        throw new ClientError("Please provide offer id to get offer details");
    }

    const offer = await Offer.findById(id).populate("appliedOn");

    res.status(201).json({
        status: "success",
        message: "Offer details fetched successfully",
        data: { offer },
    });
})

export const getAllOffers = catchAsyncError(async (req, res, next) => {
    const offers = await Offer.find({ hotelId: req.user.hotelId }).populate("appliedOn");

    res.status(201).json({
        status: "success",
        message: "All Offers fetched successfully",
        data: { offers }
    })
})

export const createOffer = catchAsyncError(async (req, res, next, session) => {
    const { hotelId } = req.user
    const { name, value, type, description, discountType, appliedOn, startDate , endDate } = req.body;

    if (!hotelId || !name || !value || !type || !discountType ||
        (type == "specific" && (!appliedOn || appliedOn.length == 0))) {
        throw new ClientError("Please provide required details to create offer");
    }
    const offer = await createOfferService({ ...req.body, hotelId }, session);
    res.status(201).json({
        status: "success",
        message: "Offer created successfully",
        data: { offer }
    })
}, true)

export const updateOffer = catchAsyncError(async (req, res, next, session) => {
    const { id } = req.params;

    if (!id) {
        throw new ClientError("Please provide offer id to update offer!");
    }

    const { name, value, type, discountType, appliedOn, startDate, endDate , appliedAbove, description} = req.body;
    if (
        !name &&
        !value &&
        !discountType &&
        !startDate &&
        !endDate &&
        !type &&
        !appliedOn &&
        !appliedAbove
    ) {
        throw new ClientError("Please provide at least one field to update the offer!");
    }

    if (type === "specific" && (!appliedOn || appliedOn.length === 0)) {
        throw new ClientError("Please provide dishes for a specific type offer!");
    }

    const offer = await updateOfferService(id, { ...req.body }, session)

    res.status(201).json({
        status: "success",
        message: "Offer updated successfully",
        data: { offer }
    })
}, true)

export const deleteOffer = catchAsyncError(async (req, res, next, session) => {
    const { id } = req.params
    if (!id) {
        throw new ClientError("Please provide offer id to delete offer!");
    }
    const offer = await deleteOfferService(id, session)

    res.status(201).json({
        status: "success",
        message: "Offer deleted successfully",
        data: { offer }
    })
}, true)

