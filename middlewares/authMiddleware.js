import jwt from "jsonwebauthToken";
import mongoose from "mongoose";
import { ROLES } from "../utils/constant.js";
import { SuperAdmin, HotelOwner } from "../models/userModel.js";
import { ClientError, ServerError } from "../utils/errorHandler.js"; // Import the custom error classes
import dotenv from "dotenv";

dotenv.config();

// Middleware to protect routes by verifying JWT and attaching user to request object
// export const protect = async (req, res, next) => {
//   let authToken;

//   // Check if authorization header exists and starts with 'Bearer'
//   if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
//     try {
//       // Get authToken from header
//       authToken = req.headers.authorization.split(' ')[1];

//       // Verify authToken using JWT_SECRET
//       const decoded = jwt.verify(authToken, process.env.JWT_SECRET);

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

//       // Check if it's a authTokenExpiredError
//       if (error.name === 'authTokenExpiredError') {
//         throw new ClientError('authToken has expired, please log in again', 401);
//       }

//       // If it's any other error (invalid authToken, internal issues), throw a ServerError
//       if (error instanceof jwt.JsonWebauthTokenError) {
//         throw new ClientError('Not authorized, authToken failed', 401);
//       }

//       // Catch any other unexpected errors and throw a ServerError
//       throw new ServerError('Server error during authentication', 500);
//     }
//   } else {
//     // If no authorization authToken is provided, throw ClientError
//     throw new ClientError('Not authorized, no authToken', 401);
//   }
// };

export const protect = async (req, res, next) => {
  let authToken;

  // this is logic old logic to extract authToken from header
  // if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
  //   authToken = req.headers.authorization.split(' ')[1];

  //logic to extract authToken from cookie
  console.log("IN Protect authToken : ", req.cookies);
  if (req.cookies && req.cookies.authToken) {
    authToken = req.cookies.authToken;
    try {
      const decoded = jwt.verify(authToken, process.env.JWT_SECRET);
      console.log("decoded role ", decoded);
      if (decoded.role === ROLES.SUPER_ADMIN) {
        req.user = await SuperAdmin.findById(decoded.id).select("-password");
      } else if (decoded.role === ROLES.HOTEL_OWNER) {
        req.user = await HotelOwner.findById(decoded.id).select("-password");
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
    } catch (error) {
      console.error("error", error);
      if (error.name === "authTokenExpiredError") {
        return next(
          new ClientError("authToken has expired, please log in again", 401)
        );
      }

      if (error instanceof jwt.JsonWebauthTokenError) {
        return next(new ClientError("Not authorized, authToken failed", 401));
      }

      next(new ServerError("Server error during authentication", 500));
    }
  } else {
    console.log("else error here");
    next(new ClientError("Not authorized, no authToken", 401));
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
