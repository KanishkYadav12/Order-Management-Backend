import mongoose from "mongoose";
import Order from "../models/orderModel.js";
import Customer from "../models/customerModel.js";
import { Category, Dish } from "../models/dishModel.js";
import Table from "../models/tableModel.js";
import Bill from "../models/billModel.js";
import Hotel from "../models/hotelModel.js";
import Offer from "../models/offerModel.js";
import { ORDER_STATUS, TABLE_STATUS, BILL_STATUS } from "../utils/constant.js";
import {
  ClientError,
  NotFoundError,
  ValidationError,
} from "../utils/errorHandler.js";
import { generateCustomerSession } from "../utils/generateToken.js";

const ORDER_POPULATE = [
  { path: "customerId", select: "_id name" },
  { path: "dishes.dishId" },
  { path: "tableId", select: "_id sequence position" },
  { path: "hotelId", select: "_id name" },
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

/**
 * Opens a diner's session at a table and returns everything the QR menu needs.
 *
 * This is the entry point for the customer flow. It issues a signed session
 * bound to this one table, which every subsequent customer request must
 * present — previously these endpoints were fully public, so anyone could
 * order on any table in any restaurant.
 */
export const onQRScanService = async ({ tableId }) => {
  const table = await Table.findOne({ _id: tableId, isDeleted: false });
  if (!table) throw new NotFoundError("Table");

  const hotelId = table.hotelId;
  const hotel = await Hotel.findById(hotelId).select(
    "name logo banner description billing serviceHours isActive"
  );

  if (!hotel?.isActive) {
    throw new ClientError(
      "This restaurant isn't taking orders right now.",
      409,
      "RESTAURANT_INACTIVE"
    );
  }

  const customer = await Customer.findOne({ tableId, hotelId });

  const [dishes, categories, offers] = await Promise.all([
    Dish.find({ hotelId, isDeleted: false }).populate("category offer"),
    Category.find({ hotelId, isDeleted: false }).sort({
      displayOrder: 1,
      name: 1,
    }),
    Offer.find({ hotelId, disable: false }),
  ]);

  // Only this table's own orders, and only the current sitting's.
  const existingOrders = customer
    ? await Order.find({ tableId, hotelId, customerId: customer._id }).populate(
        ORDER_POPULATE
      )
    : [];

  const { token: sessionToken } = generateCustomerSession({
    tableId,
    hotelId,
    customerId: customer?._id,
  });

  return {
    sessionToken,
    table: {
      _id: table._id,
      sequence: table.sequence,
      capacity: table.capacity,
      status: table.status,
    },
    hotel,
    customer,
    // `customerName` retained for the existing customer app.
    customerName: customer,
    existingOrders,
    menu: { categories, dishes, offers },
  };
};

/**
 * Creates an order for a table.
 *
 * Every dish is re-read from the database and checked against the table's own
 * hotel, so a client cannot smuggle in a dish id belonging to another
 * restaurant or one that has been deleted or is out of stock.
 */
export const addNewOrderService = async (orderData, session) => {
  const { customerName, tableId, dishes, note, status } = orderData;

  if (!Array.isArray(dishes) || dishes.length === 0) {
    throw new ValidationError("Add at least one dish to the order.");
  }

  const table = await Table.findOne({ _id: tableId, isDeleted: false }).session(
    session
  );
  if (!table) throw new NotFoundError("Table");

  const hotelId = table.hotelId;

  const dishIds = dishes.map((entry) => entry.dishId);
  const found = await Dish.find({
    _id: { $in: dishIds },
    hotelId,
    isDeleted: false,
  }).session(session);

  const foundById = new Map(found.map((dish) => [dish._id.toString(), dish]));

  const missing = dishIds.filter((id) => !foundById.has(String(id)));
  if (missing.length > 0) {
    throw new ClientError(
      "Some items are no longer on the menu. Refresh and try again.",
      409,
      "DISHES_UNAVAILABLE"
    );
  }

  const outOfStock = found.filter((dish) => dish.outOfStock);
  if (outOfStock.length > 0) {
    throw new ClientError(
      `Sorry, ${outOfStock.map((d) => d.name).join(", ")} ${outOfStock.length === 1 ? "is" : "are"} out of stock.`,
      409,
      "DISH_OUT_OF_STOCK"
    );
  }

  let customer = await Customer.findOne({ tableId, hotelId }).session(session);
  let newCustomer = null;
  let updatedTable = null;
  let isFirstOrder = false;

  if (!customer) {
    const [created] = await Customer.create(
      [{ hotelId, tableId, name: customerName?.trim() || "Guest" }],
      { session }
    );
    customer = created;
    newCustomer = created;
    isFirstOrder = true;

    updatedTable = await Table.findOneAndUpdate(
      { _id: tableId, hotelId },
      {
        status: TABLE_STATUS.OCCUPIED,
        customer: customer._id,
        occupiedAt: new Date(),
      },
      { new: true, session }
    );
  }

  const [newOrder] = await Order.create(
    [
      {
        customerId: customer._id,
        dishes: dishes.map((entry) => ({
          dishId: new mongoose.Types.ObjectId(entry.dishId),
          quantity: entry.quantity,
          // Snapshot the price so the kitchen ticket and the bill agree even
          // if the menu is repriced mid-service.
          unitPrice: foundById.get(String(entry.dishId))?.price,
          note: entry.note ?? entry.notes,
        })),
        status: status ?? ORDER_STATUS.DRAFT,
        tableId,
        hotelId,
        note: note ?? "",
        isFirstOrder,
      },
    ],
    { session }
  );

  return { newOrder, newCustomer, customer, table: updatedTable ?? table };
};

export const getOrderDetailsService = async (orderId, hotelId) => {
  const filter = { _id: orderId };
  if (hotelId) filter.hotelId = hotelId;

  const order = await Order.findOne(filter).populate(ORDER_POPULATE);
  if (!order) throw new NotFoundError("Order");
  return order;
};

export const getAllOrderService = async (hotelId, options = {}) => {
  assertScope(hotelId);

  const filter = { hotelId };
  if (options.status) filter.status = options.status;
  if (options.tableId) filter.tableId = options.tableId;
  // The kitchen board only ever wants live orders.
  if (options.activeOnly) {
    filter.status = {
      $in: [
        ORDER_STATUS.PENDING,
        ORDER_STATUS.PREPARING,
        ORDER_STATUS.READY,
      ],
    };
  }

  return Order.find(filter).populate(ORDER_POPULATE).sort({ createdAt: -1 });
};

/**
 * Moves an order through the kitchen and keeps the table in step.
 *
 * Every write here now runs inside the caller's session — the first update
 * previously omitted it, so a rollback could leave the order advanced while
 * the table state was reverted.
 */
export const updateOrderStatusService = async (
  orderId,
  hotelId,
  status,
  session
) => {
  assertScope(hotelId);

  if (!Object.values(ORDER_STATUS).includes(status)) {
    throw new ValidationError(`'${status}' is not a valid order status.`);
  }

  const order = await Order.findOneAndUpdate(
    { _id: orderId, hotelId },
    { status },
    { new: true, session }
  ).populate(ORDER_POPULATE);

  if (!order) throw new NotFoundError("Order");

  const tableId = order.tableId?._id ?? order.tableId;
  const customerId = order.customerId?._id ?? order.customerId;
  let updatedTable = null;

  if (status !== ORDER_STATUS.DRAFT) {
    // `occupiedAt` starts the table-turn clock and must not be reset each
    // time an order advances, so it is only written when currently unset.
    updatedTable = await Table.findOneAndUpdate(
      { _id: tableId, hotelId },
      [
        {
          $set: {
            status: TABLE_STATUS.OCCUPIED,
            customer: customerId,
            occupiedAt: { $ifNull: ["$occupiedAt", new Date()] },
          },
        },
      ],
      { new: true, session }
    );
  } else {
    // Reverting to draft: if nothing live remains, release the table.
    const live = await Order.countDocuments({
      tableId,
      hotelId,
      status: { $ne: ORDER_STATUS.DRAFT },
    }).session(session);

    if (live === 0) {
      updatedTable = await Table.findOneAndUpdate(
        { _id: tableId, hotelId },
        { status: TABLE_STATUS.FREE, customer: null, occupiedAt: null },
        { new: true, session }
      );
      await Bill.deleteOne({
        tableId,
        hotelId,
        status: BILL_STATUS.UNPAID,
      }).session(session);
    }
  }

  return { order, table: updatedTable };
};

/** Replaces an order's line items. Staff only. */
export const updateOrderItemsService = async (
  orderId,
  hotelId,
  dishes,
  session
) => {
  assertScope(hotelId);

  if (!Array.isArray(dishes) || dishes.length === 0) {
    throw new ValidationError("An order needs at least one dish.");
  }

  const order = await Order.findOne({ _id: orderId, hotelId }).session(session);
  if (!order) throw new NotFoundError("Order");

  if ([ORDER_STATUS.COMPLETED, ORDER_STATUS.CANCELLED].includes(order.status)) {
    throw new ClientError(
      "This order is closed and can't be changed.",
      409,
      "ORDER_CLOSED"
    );
  }

  const found = await Dish.find({
    _id: { $in: dishes.map((entry) => entry.dishId) },
    hotelId,
    isDeleted: false,
  }).session(session);

  if (found.length !== new Set(dishes.map((d) => String(d.dishId))).size) {
    throw new ClientError(
      "Some items are no longer on the menu.",
      409,
      "DISHES_UNAVAILABLE"
    );
  }

  const priceById = new Map(
    found.map((dish) => [dish._id.toString(), dish.price])
  );

  order.dishes = dishes.map((entry) => ({
    dishId: entry.dishId,
    quantity: entry.quantity,
    unitPrice: priceById.get(String(entry.dishId)),
    note: entry.note ?? entry.notes,
  }));

  await order.save({ session });
  return Order.findById(order._id).populate(ORDER_POPULATE).session(session);
};

/**
 * Deletes an order and settles the table's resulting state.
 */
export const deleteOrderService = async (orderId, hotelId, session) => {
  assertScope(hotelId);

  const order = await Order.findOne({ _id: orderId, hotelId }).session(session);
  if (!order) throw new NotFoundError("Order");

  const { tableId } = order;
  await Order.deleteOne({ _id: orderId, hotelId }).session(session);

  const remaining = await Order.find({ tableId, hotelId }).session(session);
  const customer = await Customer.findOne({ tableId, hotelId }).session(session);

  let updatedTable = null;
  const allDraft =
    remaining.length === 0 ||
    remaining.every((entry) => entry.status === ORDER_STATUS.DRAFT);

  if (allDraft) {
    updatedTable = await Table.findOneAndUpdate(
      { _id: tableId, hotelId },
      { status: TABLE_STATUS.FREE, customer: null, occupiedAt: null },
      { new: true, session }
    );

    await Bill.deleteOne({
      tableId,
      hotelId,
      status: BILL_STATUS.UNPAID,
    }).session(session);

    if (remaining.length === 0 && customer) {
      await Customer.deleteOne({ _id: customer._id }).session(session);
    }
  }

  return { order, table: updatedTable };
};
