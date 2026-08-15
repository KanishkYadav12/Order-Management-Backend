import Bill from "../models/billModel.js";
import Order from "../models/orderModel.js";
import Customer from "../models/customerModel.js";
import Table from "../models/tableModel.js";
import Hotel from "../models/hotelModel.js";
import Offer from "../models/offerModel.js";
import { Dish } from "../models/dishModel.js";
import {
  recalculateBill,
  formatInvoiceNumber,
  round2,
} from "./billingEngine.js";
import { releaseTableService } from "./tableService.js";
import { renderInvoiceHtml } from "./invoiceTemplate.js";
import sendEmail from "../utils/sendEmail.js";
import {
  ClientError,
  NotFoundError,
  ValidationError,
} from "../utils/errorHandler.js";
import { BILL_STATUS, ORDER_STATUS } from "../utils/constant.js";
import logger from "../utils/logger.js";

const BILL_POPULATE = [
  { path: "orderedItems.dishId" },
  { path: "hotelId", select: "name location phone email logo billing" },
  { path: "tableId", select: "sequence position" },
  { path: "globalOffer" },
];

const assertScope = (hotelId) => {
  if (!hotelId) {
    throw new ClientError(
      "Your account is not linked to a restaurant yet.",
      409,
      "NO_HOTEL_LINKED"
    );
  }
};

const loadBill = async (billId, hotelId, session) => {
  const bill = await Bill.findOne({ _id: billId, hotelId }).session(session);
  if (!bill) throw new NotFoundError("Bill");
  return bill;
};

const populated = (billId, session) =>
  Bill.findById(billId).populate(BILL_POPULATE).session(session);

/**
 * Re-derives every figure on a bill from its current line items.
 *
 * Called after any change — new orders, a discount edit, an offer swap — so
 * the stored totals are never a running tally that can drift.
 */
const applyTotals = async (bill, hotel, session) => {
  const dishIds = bill.orderedItems.map((item) => item.dishId).filter(Boolean);
  const dishes = await Dish.find({ _id: { $in: dishIds } })
    .populate("offer")
    .session(session);

  const dishById = new Map(dishes.map((dish) => [dish._id.toString(), dish]));

  const items = bill.orderedItems
    .map((item) => ({
      dish: dishById.get(item.dishId?.toString()),
      quantity: item.quantity,
    }))
    .filter((entry) => entry.dish);

  const globalOffer = bill.globalOffer
    ? await Offer.findOne({ _id: bill.globalOffer, hotelId: bill.hotelId }).session(session)
    : null;

  const totals = recalculateBill({
    items,
    globalOffer,
    customDiscount: bill.customDiscount,
    billingSettings: hotel?.billing ?? {},
  });

  Object.assign(bill, totals);
  return bill;
};

/**
 * Builds or refreshes the bill for a table from its non-draft orders.
 */
export const generateTableBillService = async (tableId, hotelId, session) => {
  assertScope(hotelId);

  const table = await Table.findOne({ _id: tableId, hotelId }).session(session);
  if (!table) throw new NotFoundError("Table");

  const orders = await Order.find({ tableId, hotelId })
    .session(session)
    .populate({ path: "dishes.dishId", populate: { path: "offer" } });

  if (orders.length === 0) {
    throw new ClientError(
      "There are no orders on this table yet.",
      409,
      "NO_ORDERS"
    );
  }

  const confirmed = orders.filter((order) => order.status !== ORDER_STATUS.DRAFT);
  if (confirmed.length === 0) {
    throw new ClientError(
      "Every order on this table is still a draft. Confirm them first.",
      409,
      "ALL_ORDERS_DRAFT"
    );
  }

  const openOrders = confirmed.filter((order) =>
    [ORDER_STATUS.PENDING, ORDER_STATUS.PREPARING, ORDER_STATUS.READY].includes(
      order.status
    )
  );
  if (openOrders.length > 0) {
    throw new ClientError(
      `${openOrders.length} order${openOrders.length === 1 ? " is" : "s are"} still in the kitchen. Complete them before billing.`,
      409,
      "ORDERS_IN_PROGRESS"
    );
  }

  const billable = confirmed.filter(
    (order) => order.status === ORDER_STATUS.COMPLETED
  );

  // Merge identical dishes across orders into one line.
  const merged = new Map();
  for (const order of billable) {
    for (const item of order.dishes) {
      if (!item.dishId) continue;
      const key = item.dishId._id.toString();
      merged.set(key, (merged.get(key) ?? 0) + item.quantity);
    }
  }

  if (merged.size === 0) {
    throw new ClientError(
      "There is nothing to bill on this table.",
      409,
      "NOTHING_TO_BILL"
    );
  }

  const customerId = billable[0]?.customerId ?? confirmed[0].customerId;
  const customer = await Customer.findById(customerId).session(session);

  let bill = await Bill.findOne({
    tableId,
    hotelId,
    status: BILL_STATUS.UNPAID,
  }).session(session);

  if (!bill) {
    const [created] = await Bill.create(
      [
        {
          customerId,
          tableId,
          hotelId,
          customerName: customer?.name ?? "Guest",
          customerPhone: customer?.phone,
          orderedItems: [],
          totalAmount: 0,
          finalAmount: 0,
        },
      ],
      { session }
    );
    bill = created;
  }

  bill.orderedItems = [...merged.entries()].map(([dishId, quantity]) => ({
    dishId,
    quantity,
  }));

  const hotel = await Hotel.findById(hotelId).session(session);
  await applyTotals(bill, hotel, session);
  await bill.save({ session });

  return populated(bill._id, session);
};

/**
 * Applies an edit and recomputes. Never mutates a settled bill.
 */
export const updateBillService = async (billId, hotelId, data, session) => {
  assertScope(hotelId);
  const bill = await loadBill(billId, hotelId, session);

  if (bill.status === BILL_STATUS.PAID) {
    throw new ClientError(
      "This bill is already settled and can't be changed.",
      409,
      "BILL_SETTLED"
    );
  }

  const { customerName, customerEmail, customerPhone, customDiscount, globalOffer, notes } = data;

  if (customerName !== undefined) bill.customerName = customerName.trim();
  if (customerEmail !== undefined) bill.customerEmail = customerEmail;
  if (customerPhone !== undefined) bill.customerPhone = customerPhone;
  if (notes !== undefined) bill.notes = notes;

  if (customDiscount !== undefined) {
    const parsed = Number(customDiscount);
    if (!Number.isFinite(parsed) || parsed < 0) {
      throw new ValidationError("Enter a discount of zero or more.");
    }
    // Assigned, not accumulated — this is the compounding-discount fix.
    bill.customDiscount = parsed;
  }

  if (globalOffer !== undefined) {
    if (globalOffer === null || globalOffer === "") {
      bill.globalOffer = null;
    } else {
      const offer = await Offer.findOne({
        _id: globalOffer,
        hotelId,
      }).session(session);

      if (!offer) throw new NotFoundError("Offer");
      if (offer.type !== "global") {
        throw new ClientError(
          "That offer applies to specific dishes, not the whole bill.",
          400,
          "OFFER_NOT_GLOBAL"
        );
      }
      if (offer.disable) {
        throw new ClientError("That offer is switched off.", 409, "OFFER_DISABLED");
      }
      bill.globalOffer = offer._id;
    }
  }

  const hotel = await Hotel.findById(hotelId).session(session);
  await applyTotals(bill, hotel, session);
  await bill.save({ session });

  return populated(bill._id, session);
};

/**
 * Settles a bill.
 *
 * Records who took the payment and how, assigns an invoice number, frees the
 * table and clears the sitting's orders.
 */
export const billPayService = async (billId, hotelId, data, user, session) => {
  assertScope(hotelId);
  const bill = await loadBill(billId, hotelId, session);

  if (bill.status === BILL_STATUS.PAID) {
    throw new ClientError("This bill is already settled.", 409, "BILL_SETTLED");
  }

  const hotel = await Hotel.findById(hotelId).session(session);
  await applyTotals(bill, hotel, session);

  const payments = Array.isArray(data?.payments)
    ? data.payments
    : [{ method: data?.method ?? "cash", amount: bill.finalAmount }];

  const paid = round2(
    payments.reduce((sum, payment) => sum + Number(payment.amount ?? 0), 0)
  );

  if (paid + 0.01 < bill.finalAmount) {
    throw new ClientError(
      `Payment is short by ${round2(bill.finalAmount - paid)}.`,
      400,
      "UNDERPAID"
    );
  }

  bill.payments = payments.map((payment) => ({
    method: payment.method,
    amount: Number(payment.amount),
    reference: payment.reference,
    receivedAt: new Date(),
    receivedBy: user?._id,
  }));
  bill.amountPaid = paid;
  bill.status = BILL_STATUS.PAID;
  bill.settledBy = user?._id;
  bill.settledAt = new Date();
  if (data?.customerEmail) bill.customerEmail = data.customerEmail;

  // Invoice numbers are only assigned on settlement, so an abandoned bill
  // never burns a number in the sequence.
  if (!bill.invoiceNumber && hotel) {
    const next = (hotel.billing?.invoiceCounter ?? 0) + 1;
    bill.invoiceNumber = formatInvoiceNumber(
      hotel.billing?.invoicePrefix,
      next
    );
    await Hotel.updateOne(
      { _id: hotelId },
      { $set: { "billing.invoiceCounter": next } },
      { session }
    );
  }

  await bill.save({ session });

  const table = await releaseTableService(bill.tableId, hotelId, session);
  const orders = await Order.find({ tableId: bill.tableId, hotelId }).session(session);
  const orderIds = orders.map((order) => order._id);

  await Order.deleteMany({ tableId: bill.tableId, hotelId }).session(session);
  if (bill.customerId) {
    await Customer.deleteOne({ _id: bill.customerId }).session(session);
  }

  logger.info(
    {
      billId: bill._id.toString(),
      invoiceNumber: bill.invoiceNumber,
      amount: bill.finalAmount,
      settledBy: user?._id?.toString(),
    },
    "bill settled"
  );

  const result = await populated(bill._id, session);
  return { bill: result, table, orders: orderIds };
};

/** Cancels an unsettled bill, keeping the record and the reason. */
export const voidBillService = async (billId, hotelId, reason, user) => {
  assertScope(hotelId);
  const bill = await loadBill(billId, hotelId);

  if (bill.status === BILL_STATUS.PAID) {
    throw new ClientError(
      "A settled bill can't be voided. Record a refund instead.",
      409,
      "BILL_SETTLED"
    );
  }

  bill.status = BILL_STATUS.VOID;
  bill.voidedBy = user?._id;
  bill.voidReason = reason;
  await bill.save();

  logger.warn(
    { billId: bill._id.toString(), by: user?._id?.toString(), reason },
    "bill voided"
  );

  return bill;
};

/** Paginated bill list with optional status and date filters. */
export const listBillsService = async (hotelId, query = {}) => {
  assertScope(hotelId);

  const { page = 1, limit = 20, status, from, to, search } = query;

  const filter = { hotelId };
  if (status) filter.status = status;
  if (from || to) {
    filter.createdAt = {};
    if (from) filter.createdAt.$gte = new Date(from);
    if (to) filter.createdAt.$lte = new Date(to);
  }
  if (search) {
    const escaped = String(search).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    filter.$or = [
      { customerName: { $regex: escaped, $options: "i" } },
      { invoiceNumber: { $regex: escaped, $options: "i" } },
    ];
  }

  const [bills, total] = await Promise.all([
    Bill.find(filter)
      .populate(BILL_POPULATE)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit),
    Bill.countDocuments(filter),
  ]);

  return {
    bills,
    pagination: {
      page,
      limit,
      total,
      pages: Math.ceil(total / limit) || 1,
    },
  };
};

export const getBillService = async (billId, hotelId) => {
  assertScope(hotelId);
  const bill = await Bill.findOne({ _id: billId, hotelId }).populate(BILL_POPULATE);
  if (!bill) throw new NotFoundError("Bill");
  return bill;
};

/**
 * Emails the invoice to the guest.
 *
 * The old version threw when the bill was unpaid, which meant a guest could
 * never be sent a copy of what they were about to pay. Both states are
 * allowed now; the subject line distinguishes them.
 */
export const sendBillToMailService = async (billId, hotelId, recipient) => {
  assertScope(hotelId);
  if (!recipient) throw new ValidationError("Enter an email address.");

  const bill = await getBillService(billId, hotelId);
  const html = renderInvoiceHtml(bill, bill.hotelId);

  const settled = bill.status === BILL_STATUS.PAID;
  const subject = settled
    ? `Your receipt from ${bill.hotelId?.name ?? "us"}`
    : `Your bill from ${bill.hotelId?.name ?? "us"}`;

  const delivered = await sendEmail(recipient, subject, html);
  if (!delivered) {
    throw new ClientError(
      "We couldn't send that email. Check the address and try again.",
      502,
      "EMAIL_SEND_FAILED"
    );
  }

  bill.customerEmail = recipient;
  await bill.save();

  return { sentTo: recipient, bill };
};

export const deleteBillService = async (billId, hotelId) => {
  assertScope(hotelId);
  const bill = await Bill.findOne({ _id: billId, hotelId });
  if (!bill) throw new NotFoundError("Bill");

  if (bill.status === BILL_STATUS.PAID) {
    throw new ClientError(
      "Settled bills are part of your sales record and can't be deleted.",
      409,
      "BILL_SETTLED"
    );
  }

  await bill.deleteOne();
  return bill;
};
