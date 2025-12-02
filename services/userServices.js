import { ClientError, ServerError } from "../utils/index.js";
import { HotelOwner, SuperAdmin } from "../models/userModel.js";
import Hotel from "../models/hotelModel.js";
import express from "express";
import sendEmail from "../utils/sendEmail.js";

export const getUserProfileService = async (userId) => {
  try {
    if (!userId) {
      throw new ClientError("ValidationError", "User ID is required");
    }
    const hotelOwner = await HotelOwner.findById(userId).select("-password");
    const hotel = hotelOwner ? await Hotel.findById(hotelOwner.hotelId) : null;

    if (hotelOwner) {
      hotelOwner._doc.hotelName = hotel ? hotel.name : null;
    }

    const superAdmin = await SuperAdmin.findById(userId).select("-password");
    if (!hotelOwner && !superAdmin) {
      throw new ClientError("NotFoundError", "User not found");
    }

    return hotelOwner || superAdmin;
  } catch (error) {
    throw new ServerError("Error while fetching user profile");
  }
};

export const approveHotelOwnerService = async (ownerId, session) => {
  if (!ownerId) {
    throw new ClientError("ValidationError", "Owner ID is required");
  }

  const hotelOwner = await HotelOwner.findById(ownerId).session(session);
  if (!hotelOwner) {
    throw new ClientError("NotFoundError", "Hotel owner not found");
  }

  // if (hotelOwner.isApproved) {
  //   throw new ClientError("ConflictError", "Hotel owner is already approved");
  // }

  hotelOwner.isApproved = !hotelOwner.isApproved;

  const hotel = new Hotel({
    name: `${hotelOwner.name}'s Hotel`,
    location: "Default Location",
    ownerId: hotelOwner._id,
  });

  await hotel.save({ session });
  hotelOwner.hotelId = hotel._id;

  await hotelOwner.save({ session });

  return await HotelOwner.findById(ownerId)
    .populate("hotelId")
    .session(session);
};

export const getAllHotelOwnersService = async () => {
  try {
    const hotelOwners = await HotelOwner.find().select("-password");

    if (!hotelOwners || hotelOwners.length === 0) {
      throw new ClientError("NotFoundError", "No hotel owners found");
    }

    return hotelOwners;
  } catch (error) {
    if (error instanceof ClientError) {
      throw error;
    } else throw new ServerError("Error while fetching all hotels owners");
  }
};

export const getUnApprovedOwnersService = async ({ page = 1, limit = 10 }) => {
  try {
    const skip = (page - 1) * limit;

    // Find pending hotels and return data
    const unApprovedOwners = await HotelOwner.find({ isApproved: false })
      .select("-password")
      .skip(skip)
      .limit(Number(limit)); // Ensure limit is a number

    // Get the total number of pending hotels
    const totalUnApprovedOwners = await HotelOwner.countDocuments({
      isApproved: false,
    });

    return {
      unApprovedOwners,
      pagination: {
        total: totalUnApprovedOwners,
        page: Number(page),
        totalPages: Math.ceil(totalUnApprovedOwners / limit),
        limit: Number(limit),
      },
    };
  } catch (error) {
    if (error instanceof ClientError) {
      throw error;
    } else
      throw new ServerError("Error while fetching unapproved hotel owners");
  }
};

export const getApprovedOwnersService = async ({ page = 1, limit = 10 }) => {
  try {
    const skip = (page - 1) * limit;

    // Find approved hotel owners and return data
    const approvedOwners = await HotelOwner.find({ isApproved: true })
      .select("-password")
      .skip(skip)
      .limit(Number(limit)); // Ensure limit is a number

    // Get the total number of approved hotel owners
    const totalApprovedOwners = await HotelOwner.countDocuments({
      isApproved: true,
    });

    return {
      approvedOwners,
      pagination: {
        total: totalApprovedOwners,
        page: Number(page),
        totalPages: Math.ceil(totalApprovedOwners / limit),
        limit: Number(limit),
      },
    };
  } catch (error) {
    if (error instanceof ClientError) {
      throw error;
    } else throw new ServerError("Error while fetching approved hotel owners");
  }
};
export const membershipExtenderService = async (hotelOwnerId, days) => {
  try {
    if (!hotelOwnerId) {
      throw new ClientError("ValidationError", "Owner ID is required");
    }
    const hotelOwner = await HotelOwner.findById(hotelOwnerId);

    if (!hotelOwner) {
      throw new ClientError("NotFoundError", "Hotel owner not found");
    }

    const now = new Date();
    const currentExpiry = hotelOwner.membershipExpires
      ? new Date(hotelOwner.membershipExpires)
      : null;

    const effectiveExpiry =
      currentExpiry && currentExpiry > now ? currentExpiry : now;
    effectiveExpiry.setDate(effectiveExpiry.getDate() + days);

    hotelOwner.membershipExpires = effectiveExpiry;
    
    // expire member ship id days 0
    if (days == 0) {
      const today = new Date();
      const yesterday = new Date(today);
      yesterday.setDate(today.getDate() - 1);
      hotelOwner.membershipExpires = yesterday;
    }

    await hotelOwner.save();

    return hotelOwner; // Return the updated hotel owner
  } catch (error) {
    if (error instanceof ClientError) {
      throw new error();
    } else {
      throw new ServerError("Error while extending membership", error);
    }
  }
};

export const deleteHotelOwnerService = async (ownerId) => {
  try {
    if (!ownerId) {
      throw new ClientError("ValidationError", "Owner ID is required");
    }

    const hotelOwner = await HotelOwner.findById(ownerId);

    if (!hotelOwner) {
      throw new ClientError("NotFoundError", "Hotel owner not found");
    }

    await hotelOwner.remove();

    return hotelOwner;
  } catch (error) {
    if (error instanceof ClientError) {
      throw new error();
    } else {
      throw new ServerError("Error while deleting hotel owner", error);
    }
  }
};

//send hotelowner mail for membership expired 
export const sendMailForMembershipExpiredService = async (hotelOwnerId) => {
  try {
    if (!hotelOwnerId) {
      throw new ClientError("ValidationError", "Owner ID is required");
    }

    const hotelOwner = await HotelOwner.findById(hotelOwnerId);
    if (!hotelOwner) {
      throw new ClientError("NotFoundError", "Hotel owner not found");
    }
    
    const membershipExpires = hotelOwner.membershipExpires;
    if(membershipExpires > new Date()) {
      throw new ClientError("ConflictError", "Membership is not expired yet");
    }

    //send mail to hotel owner for membership expired 
    const subject = "Membership Expired";
    const description = `Hello ${hotelOwner.name}, your membership has expired. Please renew your membership to continue enjoying our services.`;
    await sendEmail(hotelOwner.email, subject, description);
    
    return {hotelOwner, message: "Mail sent successfully",email: hotelOwner.email};  

  } catch (error) {
    if (error instanceof ClientError) {
      throw new error();
    } else {
      throw new ServerError("Error while sending mail for membership expired", error);
    }
  }
};
