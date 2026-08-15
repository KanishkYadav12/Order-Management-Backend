import express from "express";
import { protect, attachHotelId, authorize } from "../middlewares/authMiddleware.js";
import { validate } from "../middlewares/validate.js";
import { emailLimiter } from "../middlewares/security.js";
import { PERMISSIONS } from "../utils/constant.js";
import {
  getBill,
  updateBill,
  billPaid,
  getAllBills,
  deleteBill,
  voidBill,
  sendBillToMail,
} from "../controllers/billController.js";
import {
  billIdSchema,
  listBillsSchema,
  updateBillSchema,
  payBillSchema,
  voidBillSchema,
  sendBillSchema,
} from "../validators/bill.js";

const router = express.Router();

router.use(protect, attachHotelId);

router.get(
  "/",
  authorize(PERMISSIONS.BILL_READ),
  validate(listBillsSchema),
  getAllBills
);

/* Literal prefixes before `/:billId`. */
router.patch(
  "/paid/:billId",
  authorize(PERMISSIONS.BILL_PAY),
  validate(payBillSchema),
  billPaid
);

router.patch(
  "/void/:billId",
  authorize(PERMISSIONS.BILL_DELETE),
  validate(voidBillSchema),
  voidBill
);

router.post(
  "/send-bill/:billId/:email",
  authorize(PERMISSIONS.BILL_READ),
  emailLimiter,
  validate(sendBillSchema),
  sendBillToMail
);

router.post(
  "/send-bill/:billId",
  authorize(PERMISSIONS.BILL_READ),
  emailLimiter,
  validate(sendBillSchema),
  sendBillToMail
);

router.get(
  "/:billId",
  authorize(PERMISSIONS.BILL_READ),
  validate(billIdSchema),
  getBill
);

router.put(
  "/:billId",
  authorize(PERMISSIONS.BILL_WRITE),
  validate(updateBillSchema),
  updateBill
);

router.delete(
  "/:billId",
  authorize(PERMISSIONS.BILL_DELETE),
  validate(billIdSchema),
  deleteBill
);

export default router;
