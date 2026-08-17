import { catchAsyncError } from "../middlewares/catchAsyncError.js";
import {
  billPayService,
  updateBillService,
  sendBillToMailService,
  listBillsService,
  getBillService,
  deleteBillService,
  voidBillService,
} from "../services/billServices.js";

export const getAllBills = catchAsyncError(async (req, res) => {
  const { bills, pagination, totals } = await listBillsService(
    req.hotelId,
    req.query
  );

  res.status(200).json({
    status: "success",
    message: "Bills loaded",
    data: { bills, pagination, totals },
  });
});

export const getBill = catchAsyncError(async (req, res) => {
  const bill = await getBillService(req.params.billId, req.hotelId);

  res.status(200).json({
    status: "success",
    message: "Bill loaded",
    // `billDetails` is the key the existing bill screens read.
    data: { bill, billDetails: bill },
  });
});

export const updateBill = catchAsyncError(async (req, res, next, session) => {
  const bill = await updateBillService(
    req.params.billId,
    req.hotelId,
    req.body,
    session
  );

  res.status(200).json({
    status: "success",
    message: "Bill updated",
    data: { bill },
  });
}, true);

export const billPaid = catchAsyncError(async (req, res, next, session) => {
  const data = await billPayService(
    req.params.billId,
    req.hotelId,
    req.body,
    req.user,
    session
  );

  res.status(200).json({
    status: "success",
    message: "Payment recorded",
    data,
  });
}, true);

export const voidBill = catchAsyncError(async (req, res) => {
  const bill = await voidBillService(
    req.params.billId,
    req.hotelId,
    req.body.reason,
    req.user
  );

  res.status(200).json({
    status: "success",
    message: "Bill voided",
    data: { bill },
  });
});

export const deleteBill = catchAsyncError(async (req, res) => {
  const bill = await deleteBillService(req.params.billId, req.hotelId);

  res.status(200).json({
    status: "success",
    message: "Bill removed",
    data: { bill },
  });
});

export const sendBillToMail = catchAsyncError(async (req, res) => {
  // The address may arrive as a route param (legacy) or in the body.
  const recipient = req.body?.email ?? req.params.email;

  const data = await sendBillToMailService(
    req.params.billId,
    req.hotelId,
    recipient
  );

  res.status(200).json({
    status: "success",
    message: `Sent to ${data.sentTo}`,
    data,
  });
});
