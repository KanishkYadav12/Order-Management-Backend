import { catchAsyncError } from "../middlewares/catchAsyncError.js";
import { ClientError } from "../utils/errorHandler.js";
import {
  billPayService,
  updateBillService,
  sendBillToMailService,
} from "../services/billServices.js";
import Bill from "../models/billModel.js";

export const getAllBills = catchAsyncError(async (req, res, next) => {
  const hotelId = req.user.hotelId;
  4;
  console.log("HotelId : hotelId", hotelId);

  if (!hotelId) {
    throw new ClientError("Please provide hotelId to get bill");
  }

  const bills = await Bill.find({ hotelId: hotelId })
    .populate("orderedItems.dishId") // Populate Dish references with specific fields
    .populate("hotelId", "name address") // Populate Hotel references with specific fields
    .populate("tableId", "number sequence"); // Populate Table references with specific fields

  res.status(201).json({
    status: "success",
    message: "Bill fetched successfully",
    data: { bills: bills || [] },
  });
});

export const getBill = catchAsyncError(async (req, res, next) => {
  const { billId } = req.params;

  if (!billId) {
    throw new ClientError("Please provide bill ID to get bill");
  }

  const billDetails = await Bill.findById(billId)
    .populate("orderedItems.dishId") // Populate Dish references with specific fields
    .populate("hotelId", "name address") // Populate Hotel references with specific fields
    .populate("tableId", "number sequence"); // Populate Table references with specific fields

  if (!billDetails) {
    throw new ClientError("Bill not available");
  }

  res.status(201).json({
    status: "success",
    message: "Bill fetched successfully",
    data: { billDetails },
  });
});

export const deleteBill = catchAsyncError(async (req, res, next) => {
  const { billId } = req.params;

  if (!billId) {
    throw new ClientError("Please provide bill ID to get bill");
  }

  const deletedBill = await Bill.findByIdAndDelete(billId)
    .populate("orderedItems.dishId") // Populate Dish references with specific fields
    .populate("hotelId", "name address") // Populate Hotel references with specific fields
    .populate("tableId", "number sequence"); // Populate Table references with specific fields

  if (!deletedBill) {
    throw new ClientError("Bill does not exists");
  }

  res.status(201).json({
    status: "success",
    message: "Bill fetched successfully",
    data: { bill: deletedBill },
  });
});

export const updateBill = catchAsyncError(async (req, res, next, session) => {
  const { billId } = req.params;
  const { customerName, customDiscount, customerEmail, globalOffer } = req.body;

  if (
    !billId ||
    (!customerName && !customDiscount && !globalOffer && !customerEmail)
  ) {
    throw new ClientError("Please provide sufficient data to update bill");
  }

  const bill = await updateBillService({ billId, ...req.body }, session);

  res.status(201).json({
    status: "success",
    message: "Bill updated successfully",
    data: { bill },
  });
}, true);

export const billPaid = catchAsyncError(async (req, res, next, session) => {
  const { billId } = req.params;
  if (!billId) {
    throw new ClientError("Invalid input: billId is required.");
  }

  const data = await billPayService(billId, req.body, session);
  console.log("bill pay data : ", data);
  res.status(201).json({
    status: "success",
    message: "Bill Payment Successfully",
    data: data,
  });
}, true);

export const sendBillToMail = catchAsyncError(
  async (req, res, next, session) => {
    const { billId, email } = req.params;
    if (!billId) {
      throw new ClientError("Invalid input: billId is required.");
    }

    const mailId = email;

    console.log("mailId : ", mailId);

    const data = await sendBillToMailService(billId, mailId);

    res.status(201).json({
      status: "success",
      message: "Bill sent to mail Successfully",
      data: data,
    });
  }
);
