import Offer from "../models/offerModel.js";
import { Dish } from "../models/dishModel.js";
import { ClientError } from "../utils/errorHandler.js";

export const createOfferService = async (offerData, session) => {
    const { hotelId, name, value, type, discountType, description, appliedOn, disable, startDate, endDate, appliedAbove } = offerData;

    let dishDetails = null;

    // Validate `value` for discount type
    if (value < 0) {
        throw new ClientError("Value must not be less than 0!");
    }

    if (discountType === "percent" && value > 100) {
        throw new ClientError("Value must be between 0 and 100 for discount type percent!");
    }

    if (type === "specific") {
        // if (appliedAbove) {
        //     throw new ClientError("Applied above condition will not work for specific type of offer!");
        // }

        // Fetch dishes belonging to the given hotel and matching the provided IDs
        dishDetails = await Dish.find({ _id: { $in: appliedOn }, hotelId }).session(session);
        if (!dishDetails || !dishDetails.length) {
            throw new ClientError("No valid dishes found for the provided IDs to apply offer!");
        }

        // Check if any dish already has an offer applied
        const dishesWithOffer = dishDetails.filter(dish => dish.offer);
        if (dishesWithOffer.length > 0) {
            const dishIdsWithOffer = dishesWithOffer.map(dish => dish._id);
            throw new ClientError(`Some provided dishes are already associated with other offers!`);
        }

        // to ensure only valid dish pass into applied On
        const validDishIds = dishDetails.map(dish => dish._id);
        offerData.appliedOn = validDishIds;
    } else {
        offerData.appliedOn = [];
    }

    // Create the offer document
    const offer = await Offer.create({ ...offerData, session });

    if (dishDetails && dishDetails.length) {
        // Update all the fetched dishes with the new offer's ID in the offer field
        const offerId = offer._id; // Since `create` returns an array when used with transactions
        await Dish.updateMany(
            { _id: { $in: dishDetails.map(dish => dish._id) } },
            { $set: { offer: offerId } },
            { session }
        );
    }

    return offer; // Return the created offer document
};

export const updateOfferService = async (offerId, updatedData, session) => {
    const { name, value, type, discountType, disable, description, appliedAbove, startDate, endDate, logo  } = updatedData;
    let appliedOn = updatedData.appliedOn;

    // Fetch the existing offer
    const existingOffer = await Offer.findById(offerId).session(session);
    if (!existingOffer) {
        throw new ClientError('Offer not found!');
    }

    // Validate `value` is not less than 0
    if (value < 0) {
        throw new ClientError("Value must not be less than 0!");
    }

    // Determine the applicable discountType for validation
    const effectiveDiscountType = discountType || existingOffer.discountType;

    // Validate `value` for percent type
    if (effectiveDiscountType === "percent" && value > 100) {
        throw new ClientError("Value must be between 0 and 100 for discount type percent!");
    }

    // Validate `appliedAbove` for specific type
    if ((type && type === "specific") || (!type && existingOffer.type === "specific")) {
        if (appliedAbove) {
            //throw new ClientError('Applied above condition will not work for specific type of offer!');
        }
    }

    let dishDetails = null;

    // Handle validation for specific type and appliedOn
    if (type === "specific") {
        dishDetails = await Dish.find({ _id: { $in: appliedOn }, hotelId: existingOffer.hotelId }).session(session);
        if (!dishDetails || !dishDetails.length) {
            throw new ClientError('No valid dishes found for the provided IDs to apply the offer!');
        }
        const validDishIds = dishDetails.map(dish => dish._id);
        appliedOn = validDishIds;
    }

    // Remove offer from previously associated dishes if type or appliedOn changes
    if (existingOffer.type === "specific" && existingOffer.appliedOn && existingOffer.appliedOn.length > 0) {
        await Dish.updateMany(
            { _id: { $in: existingOffer.appliedOn }, offer: offerId },
            { $unset: { offer: "" } },
            { session }
        );
    }

    if (dishDetails && dishDetails.length) {
        // Update the dishes with the new offer's ID
        await Dish.updateMany(
            { _id: { $in: dishDetails.map(dish => dish._id) } },
            { $set: { offer: offerId } },
            { session }
        );
    }

    // Construct the update object explicitly
    const updateFields = {};
    if (name !== undefined) updateFields.name = name;
    if (value !== undefined) updateFields.value = value;
    if (type !== undefined) updateFields.type = type;
    if (disable !== undefined) updateFields.disable = disable;
    if (description !== undefined) updateFields.description = description;
    if (discountType !== undefined) updateFields.discountType = discountType;
    if (startDate !== undefined) updateFields.startDate = startDate;
    if (endDate !== undefined) updateFields.endDate = endDate;
    if(logo) updateFields.logo = logo
    if (type === "specific") {
        updateFields.appliedOn = appliedOn;
    } else if (type === "global") {
        updateFields.appliedOn = [];
        if (appliedAbove !== undefined) {
            updateFields.appliedAbove = appliedAbove;
        }
    }


    // Update the offer document with the provided data
    const updatedOffer = await Offer.findByIdAndUpdate(
        offerId,
        updateFields,
        { new: true, session }
    ).populate('appliedOn');

    return updatedOffer;
};

export const deleteOfferService = async (offerId, session) => {
    // Fetch the offer with the given ID
    const offer = await Offer.findById(offerId).session(session);
    if (!offer) {
        throw new ClientError('Offer not found!');
    }

    if (offer.type === 'specific' && offer.appliedOn && offer.appliedOn.length > 0) {
        // Fetch all dishes that have the offer applied
        // const dishIds = offer.appliedOn.map(dish => dish._id);
        await Dish.updateMany(
            { _id: { $in: offer.appliedOn }, offer: offerId },
            { $unset: { offer: "" } }, // Removes the offer field
            { session }
        );
    }

    // Delete the offer
    await Offer.deleteOne({ _id: offerId }, { session });

    return offer;
};
