import Offer from "../models/offerModel.js";
import { Dish } from "../models/dishModel.js";
import {
  ClientError,
  NotFoundError,
  ValidationError,
} from "../utils/errorHandler.js";

const assertScope = (hotelId) => {
  if (!hotelId) {
    throw new ClientError(
      "Your account is not linked to a restaurant yet.",
      409,
      "NO_HOTEL_LINKED"
    );
  }
};

/** Shared rules for both create and update. */
const validateOfferShape = ({ value, discountType, type, appliedOn }) => {
  if (value !== undefined && value < 0) {
    throw new ValidationError("A discount can't be negative.");
  }
  if (discountType === "percent" && value > 100) {
    throw new ValidationError("A percentage discount can't exceed 100%.");
  }
  if (type === "specific" && (!appliedOn || appliedOn.length === 0)) {
    throw new ValidationError("Choose at least one dish for this offer.");
  }
};

export const createOfferService = async (hotelId, offerData, session) => {
  assertScope(hotelId);
  validateOfferShape(offerData);

  let dishes = [];

  if (offerData.type === "specific") {
    dishes = await Dish.find({
      _id: { $in: offerData.appliedOn },
      hotelId,
      isDeleted: false,
    }).session(session);

    if (dishes.length === 0) {
      throw new ClientError(
        "None of those dishes are on your menu.",
        400,
        "NO_VALID_DISHES"
      );
    }

    const alreadyDiscounted = dishes.filter((dish) => dish.offer);
    if (alreadyDiscounted.length > 0) {
      throw new ClientError(
        `${alreadyDiscounted.map((d) => d.name).join(", ")} already ${alreadyDiscounted.length === 1 ? "has" : "have"} an offer. Remove it first.`,
        409,
        "DISH_ALREADY_DISCOUNTED"
      );
    }
  }

  // `Offer.create({ ...data, session })` wrote `session` into the document as
  // a field and ran outside the transaction. The array form with an options
  // object is the correct way to create inside a session.
  const [offer] = await Offer.create(
    [
      {
        ...offerData,
        hotelId,
        appliedOn: offerData.type === "specific" ? dishes.map((d) => d._id) : [],
      },
    ],
    { session }
  );

  if (dishes.length > 0) {
    await Dish.updateMany(
      { _id: { $in: dishes.map((d) => d._id) }, hotelId },
      { $set: { offer: offer._id } },
      { session }
    );
  }

  return Offer.findById(offer._id).populate("appliedOn").session(session);
};

export const updateOfferService = async (
  offerId,
  hotelId,
  updatedData,
  session
) => {
  assertScope(hotelId);

  const existing = await Offer.findOne({ _id: offerId, hotelId }).session(session);
  if (!existing) throw new NotFoundError("Offer");

  const nextType = updatedData.type ?? existing.type;
  const nextDiscountType = updatedData.discountType ?? existing.discountType;
  const nextValue = updatedData.value ?? existing.value;

  validateOfferShape({
    value: nextValue,
    discountType: nextDiscountType,
    type: nextType,
    appliedOn: updatedData.appliedOn ?? existing.appliedOn,
  });

  // Detach from the dishes this offer currently covers, so a dish never keeps
  // pointing at an offer that no longer applies to it.
  if (existing.appliedOn?.length > 0) {
    await Dish.updateMany(
      { _id: { $in: existing.appliedOn }, hotelId, offer: offerId },
      { $set: { offer: null } },
      { session }
    );
  }

  let nextAppliedOn = [];

  if (nextType === "specific") {
    const dishes = await Dish.find({
      _id: { $in: updatedData.appliedOn ?? existing.appliedOn },
      hotelId,
      isDeleted: false,
    }).session(session);

    if (dishes.length === 0) {
      throw new ClientError(
        "None of those dishes are on your menu.",
        400,
        "NO_VALID_DISHES"
      );
    }

    nextAppliedOn = dishes.map((dish) => dish._id);

    await Dish.updateMany(
      { _id: { $in: nextAppliedOn }, hotelId },
      { $set: { offer: offerId } },
      { session }
    );
  }

  const { hotelId: _ignored, _id: _ignoredId, ...safeData } = updatedData;

  const offer = await Offer.findOneAndUpdate(
    { _id: offerId, hotelId },
    { ...safeData, type: nextType, appliedOn: nextAppliedOn },
    { new: true, runValidators: true, session }
  ).populate("appliedOn");

  return offer;
};

export const deleteOfferService = async (offerId, hotelId, session) => {
  assertScope(hotelId);

  const offer = await Offer.findOne({ _id: offerId, hotelId }).session(session);
  if (!offer) throw new NotFoundError("Offer");

  if (offer.appliedOn?.length > 0) {
    await Dish.updateMany(
      { _id: { $in: offer.appliedOn }, hotelId, offer: offerId },
      { $set: { offer: null } },
      { session }
    );
  }

  await Offer.deleteOne({ _id: offerId, hotelId }).session(session);
  return offer;
};

export const getOfferByIdService = async (offerId, hotelId) => {
  assertScope(hotelId);
  const offer = await Offer.findOne({ _id: offerId, hotelId }).populate("appliedOn");
  if (!offer) throw new NotFoundError("Offer");
  return offer;
};

export const getAllOffersService = async (hotelId, options = {}) => {
  assertScope(hotelId);

  const filter = { hotelId };
  if (options.type) filter.type = options.type;
  if (options.activeOnly) {
    const now = new Date();
    filter.disable = false;
    filter.$and = [
      { $or: [{ startDate: null }, { startDate: { $lte: now } }] },
      { $or: [{ endDate: null }, { endDate: { $gte: now } }] },
    ];
  }

  return Offer.find(filter).populate("appliedOn").sort({ createdAt: -1 });
};
