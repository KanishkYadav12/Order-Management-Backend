import { protect, attachHotelId } from "./authMiddleware.js";
import { requireCustomerSession } from "./customerSession.js";
import { ClientError } from "../utils/errorHandler.js";

/**
 * Accepts either an authenticated staff member or a QR diner holding a valid
 * table session, and rejects anonymous callers.
 *
 * The customer ordering routes need this: a waiter takes orders from the
 * dashboard, and a diner takes their own from the QR menu, but neither route
 * may be open to the public — which is exactly what they were.
 */
export const staffOrCustomer = (req, res, next) => {
  const hasBearer = String(req.headers.authorization ?? "").startsWith("Bearer ");

  if (hasBearer) {
    return protect(req, res, (err) => {
      if (err) return next(err);
      return attachHotelId(req, res, next);
    });
  }

  const hasSession =
    Boolean(req.headers["x-customer-session"]) ||
    Boolean(req.body?.customerSession);

  if (hasSession) return requireCustomerSession(req, res, next);

  return next(
    new ClientError(
      "Scan the QR code at your table, or sign in to continue.",
      401,
      "NO_CREDENTIALS"
    )
  );
};

export default staffOrCustomer;
