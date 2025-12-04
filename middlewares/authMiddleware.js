import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import { ROLES } from "../utils/constant.js";
import { SuperAdmin, HotelOwner } from "../models/userModel.js";
import { ClientError, ServerError } from "../utils/errorHandler.js"; // Import the custom error classes
import dotenv from "dotenv";

dotenv.config();

// Middleware to protect routes by verifying JWT and attaching user to request object
// export const protect = async (req, res, next) => {
//   let token;

//   // Check if authorization header exists and starts with 'Bearer'
//   if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
//     try {
//       // Get token from header
//       token = req.headers.authorization.split(' ')[1];

//       // Verify token using JWT_SECRET
//       const decoded = jwt.verify(token, process.env.JWT_SECRET);

//       // Dynamically attach the user model based on the role (SuperAdmin or HotelOwner)
//       if (decoded.role === ROLES.SUPER_ADMIN) {
//         req.user = await SuperAdmin.findById(decoded.id).select('-password');
//       } else if (decoded.role === ROLES.HOTEL_OWNER) {
//         req.user = await HotelOwner.findById(decoded.id).select('-password');
//       }

//       // If user is not found, throw ClientError
//       if (!req.user) {
//         throw new ClientError('User not found', 401);
//       }

//       // If user is found, move to the next middleware or route handler

//       if(req.user.isApproved === false){
//         throw new ClientError('User not approved', 401);
//       }

//       if( req.user.role==ROLES.HOTEL_OWNER && ( req.user.membershipExpires==null || req.user.membershipExpires < new Date())){
//         throw new ClientError('Membership expired', 401);
//       }

//       next();
//     } catch (error) {
//       console.error(error);

//       // Check if it's a tokenExpiredError
//       if (error.name === 'tokenExpiredError') {
//         throw new ClientError('token has expired, please log in again', 401);
//       }

//       // If it's any other error (invalid token, internal issues), throw a ServerError
//       if (error instanceof jwt.JsonWebtokenError) {
//         throw new ClientError('Not authorized, token failed', 401);
//       }

//       // Catch any other unexpected errors and throw a ServerError
//       throw new ServerError('Server error during authentication', 500);
//     }
//   } else {
//     // If no authorization token is provided, throw ClientError
//     throw new ClientError('Not authorized, no token', 401);
//   }
// };

export const protect = async (req, res, next) => {
  try {
    const authHeader =
      req.headers["authorization"] || req.headers["Authorization"] || "";
    const token =
      authHeader && authHeader.startsWith("Bearer ")
        ? authHeader.split(" ")[1]
        : null;

    if (!token) {
      console.log("No token found in Authorization header");
      return next(new ClientError("Not authorized, no token", 401));
    }

    let decoded;
    try {
      // ✅ CHANGE THIS: Use ACCESS_TOKEN_SECRET instead of JWT_SECRET
      decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
      console.log("IN Protect decoded : ", decoded);
    } catch (err) {
      console.error("JWT verify error:", err);
      if (err.name === "TokenExpiredError") {
        return next(
          new ClientError("token has expired, please log in again", 401)
        );
      }
      if (err instanceof jwt.JsonWebTokenError) {
        return next(new ClientError("Not authorized, token failed", 401));
      }
      return next(new ServerError("Server error during authentication", 500));
    }

    const userId = decoded.sub || decoded.id || decoded._id;
    const userRole = decoded.role;

    if (!userId) {
      return next(
        new ClientError("Invalid token payload: missing user id", 401)
      );
    }

    if (userRole === ROLES.SUPER_ADMIN) {
      req.user = await SuperAdmin.findById(userId).select("-password");
    } else if (userRole === ROLES.HOTEL_OWNER) {
      req.user = await HotelOwner.findById(userId).select("-password");
    } else {
      req.user =
        (await SuperAdmin.findById(userId).select("-password")) ||
        (await HotelOwner.findById(userId).select("-password"));
    }

    if (!req.user) {
      return next(new ClientError("User not found", 401));
    }

    if (!req.user.isApproved) {
      return next(new ClientError("User not approved", 401));
    }

    if (
      req.user.role === ROLES.HOTEL_OWNER &&
      (!req.user.membershipExpires || req.user.membershipExpires < new Date())
    ) {
      return next(new ClientError("Membership expired", 401));
    }

    next();
  } catch (err) {
    console.error("protect middleware error:", err);
    return next(new ServerError("Server error during authentication", 500));
  }
};
export const attachHotelId = (req, res, next) => {
  const { user } = req;

  if (user.role === ROLES.SUPER_ADMIN) {
    const { hotelId } = req.body;

    if (!hotelId) {
      return next(
        new ClientError(
          "Hotel ID is required for super admin role to access hotel resources",
          400
        )
      );
    }

    req.user.hotelId = hotelId;
  }
  next();
};
// Middleware to check if the logged-in user is a SuperAdmin
export const superAdminOnly = (req, res, next) => {
  // Ensure only SuperAdmins can access this route

  if (req.user.role !== ROLES.SUPER_ADMIN) {
    return next(
      new ClientError("ForbiddenError", "Access denied. SuperAdmin only.")
    );
  }

  next();
};

export const validateOwnership = async (req, res, next) => {
  const { user } = req;

  if (user.role === ROLES.SUPER_ADMIN) {
    return next();
  }

  try {
    const resource = req.baseUrl.split("/")[3];
    console.log("resource", resource);

    const resourceIdKey = Object.keys(req.params).find((key) =>
      key.toLowerCase().includes("id")
    );

    if (!resourceIdKey) {
      return next(new ClientError("Resource ID not provided", 400));
    }

    const resourceId = req.params[resourceIdKey];
    const modelString =
      resource.charAt(0).toUpperCase() + resource.slice(1, -1);
    console.log("modelString :", modelString);

    const ResourceModel =
      mongoose.models[modelString] || mongoose.model(modelString);

    console.log("resourceId", resourceId);
    console.log("resourceModel", ResourceModel);

    if (!ResourceModel) {
      return next(new ClientError(`Invalid resource: ${resource}`, 400));
    }

    const resourceData = await ResourceModel.findById(resourceId);
    console.log("resourceData", resourceData);

    if (!resourceData) {
      return next(new ClientError(`${resource} not found`, 404));
    }

    if (!resourceData.hotelId.equals(user.hotelId)) {
      return next(
        new ClientError(
          "Access denied. This resource does not belong to your hotel.",
          403
        )
      );
    }

    next();
  } catch (error) {
    next(error);
  }
};

// export const validateOwnership = async (req, res, next) => {
//   const { user } = req;

//   // Only HotelOwners need ownership validation
//   if (user.role == ROLES.SUPER_ADMIN) {
//     return next();
//   }

//   try {
//     // Dynamically extract resource name from URL path (tables, bills, etc.)
//     const resource = req.baseUrl.split('/')[3]; // Example: /tables/:id or /bills/:id
//     const resourceIdKey = Object.keys(req.params).find((key) => key.toLowerCase().includes('id'));

//     if (!resourceIdKey) {
//       throw new ClientError('Resource ID not provided', 400);
//     }

//     const resourceId = req.params[resourceIdKey];

//     // Dynamically load the resource model from Mongoose based on resource name
//     const ResourceModel = mongoose.models[resource.charAt(0).toUpperCase() + resource.slice(1)];

//     if (!ResourceModel) {
//       throw new ClientError(`Invalid resource: ${resource}`, 400);
//     }

//     // Fetch the resource data by ID
//     const resourceData = await ResourceModel.findById(resourceId);
//     if (!resourceData) {
//       throw new ClientError(`${resource} not found`, 404);
//     }

//     // Check if the resource belongs to the same hotel as the hotel owner
//     if (!resourceData.hotelId.equals(user.hotelId)) {
//       throw new ClientError('Access denied. This resource does not belong to your hotel.', 403);
//     }

//     // Proceed to the next middleware if ownership is validated
//     next();
//   } catch (error) {
//     console.error(error);

//     // Handle specific ClientError scenarios
//     if (error instanceof ClientError) {
//       return res.status(error.statusCode).json({ success: false, message: error.message });
//     }

//     // Any unexpected error is treated as a server error
//     throw new ServerError('Server error during ownership validation', 500);
//   }
// };
