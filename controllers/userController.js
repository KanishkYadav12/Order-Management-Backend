import { catchAsyncError } from "../middlewares/catchAsyncError.js";
import {
  getUserProfileService,
  approveHotelOwnerService,
  getAllHotelOwnersService,
  getUnApprovedOwnersService,
  getApprovedOwnersService,
  membershipExtenderService,
  deleteHotelOwnerService,
  sendMailForMembershipExpiredService,
  updateOwnProfileService,
} from "../services/userServices.js";
import env from "../config/env.js";

export const getUserProfile = catchAsyncError(async (req, res) => {
  const user = await getUserProfileService(req.user._id);

  res.status(200).json({
    status: "success",
    message: "Profile loaded",
    data: { user },
  });
});

/**
 * Self-service profile update.
 *
 * The previous version passed the whole request body into `findByIdAndUpdate`,
 * so a user could set their own `email` — and anything else on the schema.
 */
export const updateOwner = catchAsyncError(async (req, res) => {
  const owner = await updateOwnProfileService(
    req.user._id,
    req.user.role,
    req.body
  );

  res.status(200).json({
    status: "success",
    message: "Profile updated",
    data: { owner },
  });
});

export const approveHotelOwner = catchAsyncError(
  async (req, res, next, session) => {
    const owner = await approveHotelOwnerService(req.params.ownerId, session);

    res.status(200).json({
      status: "success",
      message: `Owner ${owner.isApproved ? "approved" : "un-approved"}`,
      data: { hotelOwner: owner },
    });
  },
  true
);

export const getAllHotelOwners = catchAsyncError(async (req, res) => {
  const { hotelOwners, pagination } = await getAllHotelOwnersService(req.query);

  res.status(200).json({
    status: "success",
    message: "Owners loaded",
    data: { hotelOwners, pagination },
  });
});

export const getUnApprovedOwners = catchAsyncError(async (req, res) => {
  const { unApprovedOwners, pagination } = await getUnApprovedOwnersService(
    req.query
  );

  res.status(200).json({
    status: "success",
    message: "Pending owners loaded",
    data: { unApprovedOwners, pagination },
  });
});

export const getApprovedOwners = catchAsyncError(async (req, res) => {
  const { approvedOwners, pagination } = await getApprovedOwnersService(
    req.query
  );

  res.status(200).json({
    status: "success",
    message: "Approved owners loaded",
    data: { approvedOwners, pagination },
  });
});

export const membershipExtender = catchAsyncError(async (req, res) => {
  const owner = await membershipExtenderService(
    req.params.hotelOwnerId,
    req.body.days
  );

  res.status(200).json({
    status: "success",
    message: "Subscription updated",
    data: { updatedHotelOwner: owner },
  });
});

export const deleteHotelOwner = catchAsyncError(async (req, res) => {
  const owner = await deleteHotelOwnerService(req.params.ownerId);

  res.status(200).json({
    status: "success",
    message: "Owner suspended",
    data: { owner },
  });
});

export const sendMailForMembershipExpired = catchAsyncError(async (req, res) => {
  const data = await sendMailForMembershipExpiredService(
    req.params.hotelOwnerId
  );

  res.status(200).json({
    status: "success",
    message: "Reminder sent",
    data,
  });
});

