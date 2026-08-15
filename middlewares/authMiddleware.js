import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import { ROLES, hasPermission } from "../utils/constant.js";
import { SuperAdmin, HotelOwner } from "../models/userModel.js";
import Hotel from "../models/hotelModel.js";
import { verifyAccessToken } from "../utils/generateToken.js";
import {
  AuthError,
  ForbiddenError,
  ClientError,
  NotFoundError,
} from "../utils/errorHandler.js";
import logger from "../utils/logger.js";

/**
 * Authenticates the request and loads the user.
 *
 * Every failure path returns a real 401 rather than the 500 the previous
 * implementation produced, which is what allows the dashboard's 401
 * interceptor to clear a dead session and redirect to login.
 */
export const protect = async (req, res, next) => {
  try {
    const header = req.headers.authorization ?? "";
    const token = header.startsWith("Bearer ") ? header.slice(7).trim() : null;

    if (!token) {
      return next(new AuthError("You need to sign in to do that."));
    }

    let decoded;
    try {
      decoded = verifyAccessToken(token);
    } catch (err) {
      if (err instanceof jwt.TokenExpiredError) {
        return next(
          new ClientError(
            "Your session has expired. Please sign in again.",
            401,
            "TOKEN_EXPIRED"
          )
        );
      }
      return next(new AuthError("Your session is not valid."));
    }

    const userId = decoded.sub;
    if (!userId || !mongoose.isValidObjectId(userId)) {
      return next(new AuthError("Your session is not valid."));
    }

    // The role in the token selects the collection. It is only a routing hint —
    // authorisation always reads the freshly loaded document below, so a
    // tampered role claim cannot escalate anything.
    const Model = decoded.role === ROLES.SUPER_ADMIN ? SuperAdmin : HotelOwner;
    let user = await Model.findById(userId).select("-password");

    // Fall back to the other collection if the role claim disagreed with
    // reality (e.g. a token minted before a role change).
    if (!user) {
      const Other = Model === SuperAdmin ? HotelOwner : SuperAdmin;
      user = await Other.findById(userId).select("-password");
    }

    if (!user) {
      return next(new AuthError("Your account could not be found."));
    }

    if (!user.isApproved) {
      return next(
        new ClientError(
          "Your account is awaiting approval.",
          403,
          "ACCOUNT_NOT_APPROVED"
        )
      );
    }

    if (user.isSuspended) {
      return next(
        new ClientError(
          "This account has been suspended.",
          403,
          "ACCOUNT_SUSPENDED"
        )
      );
    }

    // Membership only gates tenant accounts, and only the owner's own
    // subscription — staff inherit their hotel's standing.
    if (
      user.role === ROLES.HOTEL_OWNER &&
      (!user.membershipExpires || user.membershipExpires < new Date())
    ) {
      return next(
        new ClientError(
          "Your subscription has expired. Please renew to continue.",
          402,
          "MEMBERSHIP_EXPIRED"
        )
      );
    }

    req.user = user;
    req.auth = { userId: user._id, role: user.role, hotelId: user.hotelId };
    next();
  } catch (err) {
    logger.error({ err }, "authentication failed unexpectedly");
    next(err);
  }
};

/**
 * Asserts the caller is scoped to a hotel before any tenant query runs.
 *
 * This is the guard against the `find({ hotelId: undefined })` class of bug:
 * without it, an owner whose hotel was never created queries with an
 * undefined scope and — depending on driver settings — can match every
 * tenant's documents.
 */
export const requireHotel = (req, res, next) => {
  const hotelId = req.scopeHotelId ?? req.user?.hotelId;

  if (!hotelId) {
    return next(
      new ClientError(
        "Your account is not linked to a restaurant yet.",
        409,
        "NO_HOTEL_LINKED"
      )
    );
  }

  req.hotelId = hotelId;
  next();
};

/**
 * Lets a super admin act within a specific hotel via `?hotelId=`.
 *
 * The previous version read `req.body.hotelId` — impossible on GET, so every
 * hotel-scoped list was unusable for a super admin — and wrote the unvalidated
 * value straight onto `req.user`.
 */
export const attachHotelId = async (req, res, next) => {
  try {
    if (req.user.role !== ROLES.SUPER_ADMIN) {
      req.hotelId = req.user.hotelId;
      return requireHotel(req, res, next);
    }

    const requested =
      req.query.hotelId ?? req.body?.hotelId ?? req.params?.hotelId;

    if (!requested) {
      return next(
        new ClientError(
          "Add ?hotelId= to choose which restaurant to act on.",
          400,
          "HOTEL_ID_REQUIRED"
        )
      );
    }

    if (!mongoose.isValidObjectId(requested)) {
      return next(new ClientError("That restaurant id is not valid.", 400));
    }

    const exists = await Hotel.exists({ _id: requested });
    if (!exists) return next(new NotFoundError("Restaurant"));

    req.scopeHotelId = requested;
    req.hotelId = requested;
    next();
  } catch (err) {
    next(err);
  }
};

/** Platform administration only. */
export const superAdminOnly = (req, res, next) => {
  if (req.user?.role !== ROLES.SUPER_ADMIN) {
    return next(new ForbiddenError("This area is restricted to administrators."));
  }
  next();
};

/**
 * Permission gate.
 *
 *   router.post("/", protect, authorize(PERMISSIONS.MENU_WRITE), createDish)
 */
export const authorize =
  (...permissions) =>
  (req, res, next) => {
    const role = req.user?.role;
    if (!role) return next(new AuthError("You need to sign in to do that."));

    const missing = permissions.filter((p) => !hasPermission(role, p));
    if (missing.length > 0) {
      logger.warn(
        { role, missing, path: req.originalUrl },
        "permission denied"
      );
      return next(
        new ForbiddenError("Your role does not allow that action.")
      );
    }
    next();
  };

/** Role gate, for the cases where a permission would be too fine-grained. */
export const requireRole =
  (...roles) =>
  (req, res, next) => {
    if (!roles.includes(req.user?.role)) {
      return next(new ForbiddenError("Your role does not allow that action."));
    }
    next();
  };

/**
 * Maps a mounted route prefix to the model that owns its `:id` parameter.
 *
 * The previous implementation derived the model name from the URL by
 * capitalising and stripping the trailing "s" — which produced "Dishe" for
 * /dishes and would silently fail open on any prefix that did not pluralise
 * regularly.
 */
const RESOURCE_MODELS = {
  bills: "Bill",
  offers: "Offer",
  orders: "Order",
  tables: "Table",
  dishes: "Dish",
  categories: "Category",
  ingredients: "Ingredient",
  hotels: "Hotel",
};

/**
 * Confirms the addressed resource belongs to the caller's hotel.
 *
 * Reads the first `*id*` route parameter, loads the document, and compares
 * its `hotelId`. A missing model mapping is treated as a failure, never as a
 * pass — this middleware must fail closed.
 */
export const validateOwnership = async (req, res, next) => {
  try {
    const { user } = req;

    if (user.role === ROLES.SUPER_ADMIN) return next();

    const hotelId = req.hotelId ?? user.hotelId;
    if (!hotelId) {
      return next(
        new ClientError(
          "Your account is not linked to a restaurant yet.",
          409,
          "NO_HOTEL_LINKED"
        )
      );
    }

    const prefix = req.baseUrl.split("/").filter(Boolean).pop();
    const modelName = RESOURCE_MODELS[prefix];

    if (!modelName) {
      logger.error({ prefix, baseUrl: req.baseUrl }, "no ownership model mapped");
      return next(
        new ForbiddenError("This resource cannot be verified for access.")
      );
    }

    const idKey = Object.keys(req.params).find((key) =>
      key.toLowerCase().endsWith("id")
    );
    if (!idKey) return next(new ClientError("Missing resource id.", 400));

    const resourceId = req.params[idKey];
    if (!mongoose.isValidObjectId(resourceId)) {
      return next(new ClientError("That id is not valid.", 400));
    }

    const Model = mongoose.model(modelName);

    // Hotels are matched on their own _id; everything else on hotelId.
    const scopeField = modelName === "Hotel" ? "_id" : "hotelId";
    const doc = await Model.findOne({
      _id: resourceId,
      [scopeField]: hotelId,
    }).select("_id");

    if (!doc) {
      // Deliberately a 404 rather than a 403: telling an attacker that a
      // resource exists but belongs to someone else is itself a disclosure.
      return next(new NotFoundError(modelName));
    }

    next();
  } catch (err) {
    next(err);
  }
};

export default protect;
