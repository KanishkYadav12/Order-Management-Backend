import Hotel from "../models/hotelModel.js";
import { HotelOwner } from "../models/userModel.js";
import { ROLES } from "../utils/constant.js";
import { NotFoundError, ForbiddenError } from "../utils/errorHandler.js";

/**
 * Fields a tenant may change on their own restaurant. Anything outside this
 * list — ownerId above all — is unreachable from a request body.
 */
const OWNER_EDITABLE = [
  "name",
  "location",
  "logo",
  "banner",
  "description",
  "phone",
  "email",
];

const BILLING_EDITABLE = [
  "gstin",
  "taxRatePercent",
  "pricesIncludeTax",
  "serviceChargePercent",
  "currency",
  "currencySymbol",
  "roundOffEnabled",
  "invoicePrefix",
  "footerNote",
];

export const getHotelByIdService = async (user, hotelId) => {
  // A tenant always resolves to their own hotel regardless of what was asked
  // for, so a guessed id in the URL cannot widen their access.
  const targetId = user.role === ROLES.SUPER_ADMIN ? hotelId : user.hotelId;

  const hotel = await Hotel.findById(targetId).populate("ownerId", "name email phone");
  if (!hotel) throw new NotFoundError("Restaurant");

  return hotel;
};

export const updateHotelService = async (user, hotelId, updates) => {
  const targetId = user.role === ROLES.SUPER_ADMIN ? hotelId : user.hotelId;

  const hotel = await Hotel.findById(targetId);
  if (!hotel) throw new NotFoundError("Restaurant");

  for (const field of OWNER_EDITABLE) {
    if (updates[field] !== undefined) hotel[field] = updates[field];
  }

  if (updates.billing) {
    for (const field of BILLING_EDITABLE) {
      if (updates.billing[field] !== undefined) {
        hotel.billing[field] = updates.billing[field];
      }
    }
  }

  if (updates.serviceHours) {
    Object.assign(hotel.serviceHours, updates.serviceHours);
  }

  await hotel.save();
  return hotel;
};

/** Platform-level: removing a restaurant is never a tenant action. */
export const deleteHotelService = async (user, hotelId) => {
  if (user.role !== ROLES.SUPER_ADMIN) {
    throw new ForbiddenError("Only an administrator can remove a restaurant.");
  }

  const hotel = await Hotel.findById(hotelId);
  if (!hotel) throw new NotFoundError("Restaurant");

  // Soft-deactivate rather than drop: bills and orders still reference it.
  hotel.isActive = false;
  await hotel.save();

  await HotelOwner.updateMany({ hotelId }, { isSuspended: true });

  return hotel;
};

export const getAllHotelsService = async ({ page = 1, limit = 20, search } = {}) => {
  const filter = {};
  if (search) {
    const escaped = String(search).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    filter.name = { $regex: escaped, $options: "i" };
  }

  const [hotels, total] = await Promise.all([
    Hotel.find(filter)
      .populate("ownerId", "name email membershipExpires isApproved")
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit),
    Hotel.countDocuments(filter),
  ]);

  return {
    hotels,
    pagination: { page, limit, total, pages: Math.ceil(total / limit) || 1 },
  };
};
