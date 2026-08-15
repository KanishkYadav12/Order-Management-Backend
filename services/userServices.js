import { HotelOwner, SuperAdmin } from "../models/userModel.js";
import Hotel from "../models/hotelModel.js";
import { ROLES } from "../utils/constant.js";
import {
  ClientError,
  NotFoundError,
  ValidationError,
} from "../utils/errorHandler.js";
import { sendMembershipExpiredEmail } from "../utils/sendEmail.js";
import logger from "../utils/logger.js";

export const getUserProfileService = async (userId) => {
  if (!userId) throw new ValidationError("Missing user id.");

  const user =
    (await HotelOwner.findById(userId)) ?? (await SuperAdmin.findById(userId));

  if (!user) throw new NotFoundError("User");

  // Attach the restaurant name the dashboard header displays. Uses a plain
  // object rather than mutating `_doc`, which bypassed the toJSON transform
  // that strips secrets.
  const profile = user.toJSON();

  if (user.hotelId) {
    const hotel = await Hotel.findById(user.hotelId).select("name logo billing");
    profile.hotelName = hotel?.name ?? null;
    profile.hotel = hotel ?? null;
  }

  return profile;
};

/**
 * Approves or un-approves a restaurant owner.
 *
 * This used to create a brand-new Hotel on every call. Because approval is a
 * toggle, approving twice created two restaurants and orphaned the first —
 * along with its menu and tables. The hotel is created once at signup now, so
 * this only backfills for accounts that predate that change.
 */
export const approveHotelOwnerService = async (ownerId, session) => {
  const owner = await HotelOwner.findById(ownerId).session(session);
  if (!owner) throw new NotFoundError("Restaurant owner");

  owner.isApproved = !owner.isApproved;

  if (!owner.hotelId) {
    const [hotel] = await Hotel.create(
      [
        {
          name: `${owner.name}'s Restaurant`,
          location: "",
          ownerId: owner._id,
        },
      ],
      { session }
    );
    owner.hotelId = hotel._id;
    logger.info(
      { ownerId: owner._id.toString(), hotelId: hotel._id.toString() },
      "backfilled hotel for legacy owner"
    );
  }

  // A newly approved owner with no subscription gets a 14-day trial, so an
  // approved account is never immediately blocked by the membership check.
  if (owner.isApproved && !owner.membershipExpires) {
    owner.membershipExpires = new Date(Date.now() + 14 * 24 * 60 * 60 * 1000);
  }

  await owner.save({ session });

  return HotelOwner.findById(ownerId).populate("hotelId").session(session);
};

/** Paged owner list. An empty result is a valid answer, not an error. */
const listOwners = async (filter, { page = 1, limit = 10, search } = {}) => {
  const query = { ...filter, role: ROLES.HOTEL_OWNER };

  if (search) {
    const escaped = String(search).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    query.$or = [
      { name: { $regex: escaped, $options: "i" } },
      { email: { $regex: escaped, $options: "i" } },
    ];
  }

  const [owners, total] = await Promise.all([
    HotelOwner.find(query)
      .populate("hotelId", "name location isActive")
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(Number(limit)),
    HotelOwner.countDocuments(query),
  ]);

  return {
    owners,
    pagination: {
      total,
      page: Number(page),
      limit: Number(limit),
      totalPages: Math.ceil(total / limit) || 1,
    },
  };
};

export const getAllHotelOwnersService = async (options = {}) => {
  const { owners, pagination } = await listOwners({}, options);
  return { hotelOwners: owners, pagination };
};

export const getUnApprovedOwnersService = async (options) => {
  const { owners, pagination } = await listOwners({ isApproved: false }, options);
  return { unApprovedOwners: owners, pagination };
};

export const getApprovedOwnersService = async (options) => {
  const { owners, pagination } = await listOwners({ isApproved: true }, options);
  return { approvedOwners: owners, pagination };
};

/**
 * Extends a subscription by `days`, counting from whichever is later: today
 * or the current expiry. Passing 0 expires the account immediately.
 */
export const membershipExtenderService = async (hotelOwnerId, days) => {
  const owner = await HotelOwner.findById(hotelOwnerId);
  if (!owner) throw new NotFoundError("Restaurant owner");

  const parsedDays = Number(days);
  if (!Number.isInteger(parsedDays) || parsedDays < 0) {
    throw new ValidationError("Enter a whole number of days.");
  }

  if (parsedDays === 0) {
    owner.membershipExpires = new Date(Date.now() - 24 * 60 * 60 * 1000);
  } else {
    const now = new Date();
    const current = owner.membershipExpires
      ? new Date(owner.membershipExpires)
      : null;
    const base = current && current > now ? current : now;
    base.setDate(base.getDate() + parsedDays);
    owner.membershipExpires = base;
  }

  await owner.save({ validateBeforeSave: false });

  logger.info(
    {
      ownerId: owner._id.toString(),
      days: parsedDays,
      expiresAt: owner.membershipExpires,
    },
    "membership updated"
  );

  return owner;
};

/**
 * Suspends an owner and deactivates their restaurant.
 *
 * A hard delete would orphan every bill, order and table referencing them,
 * and destroy the sales record. `hotelOwner.remove()` also no longer exists
 * in Mongoose 8, so the previous implementation threw at runtime.
 */
export const deleteHotelOwnerService = async (ownerId) => {
  const owner = await HotelOwner.findById(ownerId);
  if (!owner) throw new NotFoundError("Restaurant owner");

  owner.isSuspended = true;
  owner.isApproved = false;
  owner.refreshTokens = [];
  owner.tokensValidFrom = new Date();
  await owner.save({ validateBeforeSave: false });

  if (owner.hotelId) {
    await Hotel.updateOne({ _id: owner.hotelId }, { isActive: false });
  }

  logger.warn({ ownerId: owner._id.toString() }, "owner suspended");
  return owner;
};

export const sendMailForMembershipExpiredService = async (hotelOwnerId) => {
  const owner = await HotelOwner.findById(hotelOwnerId);
  if (!owner) throw new NotFoundError("Restaurant owner");

  if (owner.membershipExpires && owner.membershipExpires > new Date()) {
    throw new ClientError(
      "This subscription hasn't expired yet.",
      409,
      "MEMBERSHIP_ACTIVE"
    );
  }

  const expiredOn = owner.membershipExpires
    ? new Date(owner.membershipExpires).toLocaleDateString("en-IN", {
        day: "2-digit",
        month: "short",
        year: "numeric",
      })
    : "an earlier date";

  await sendMembershipExpiredEmail(owner.email, { name: owner.name, expiredOn });

  return { email: owner.email, message: "Reminder sent" };
};

/** Profile self-update. Never touches role, approval or hotel. */
export const updateOwnProfileService = async (userId, role, updates) => {
  const Model = role === ROLES.SUPER_ADMIN ? SuperAdmin : HotelOwner;

  const user = await Model.findById(userId);
  if (!user) throw new NotFoundError("User");

  for (const field of ["name", "logo", "gender", "phone"]) {
    if (updates[field] !== undefined) user[field] = updates[field];
  }

  await user.save({ validateBeforeSave: false });
  return user;
};
