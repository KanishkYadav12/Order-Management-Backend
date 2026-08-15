import { catchAsyncError } from "../middlewares/catchAsyncError.js";
import {
  createStaffTokenRequest,
  createCustomerTokenRequest,
} from "../services/ablyService.js";
import { ClientError } from "../utils/errorHandler.js";
import Table from "../models/tableModel.js";

/**
 * Issues an Ably token request for the signed-in staff member.
 *
 * The client passes the returned object straight to Ably, which exchanges it
 * for a token. The root key never leaves the server.
 */
export const getStaffRealtimeToken = catchAsyncError(async (req, res) => {
  const { hotelId, _id: userId } = req.user;

  if (!hotelId) {
    throw new ClientError(
      "Your account is not linked to a restaurant yet.",
      409,
      "NO_HOTEL_LINKED"
    );
  }

  const tokenRequest = await createStaffTokenRequest(hotelId, userId);

  res.status(200).json({
    status: "success",
    message: "Realtime token issued",
    data: { tokenRequest, channel: `hotel-${hotelId.toString()}` },
  });
});

/**
 * Issues an Ably token request for a QR customer.
 *
 * Requires a valid customer session for the table in question, so a visitor
 * cannot subscribe to a table they are not seated at.
 */
export const getCustomerRealtimeToken = catchAsyncError(async (req, res) => {
  const { tableId } = req.params;

  if (req.customerSession?.tableId !== tableId) {
    throw new ClientError(
      "This session is not valid for that table.",
      403,
      "TABLE_SESSION_MISMATCH"
    );
  }

  const table = await Table.findById(tableId).select("_id");
  if (!table) throw new ClientError("Table not found.", 404, "NOT_FOUND");

  const tokenRequest = await createCustomerTokenRequest(
    tableId,
    req.customerSession.sessionId
  );

  res.status(200).json({
    status: "success",
    message: "Realtime token issued",
    data: { tokenRequest, channel: `table-${tableId}` },
  });
});
