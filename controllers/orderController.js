import { catchAsyncError } from "../middlewares/catchAsyncError.js";
import {
  addNewOrderService,
  deleteOrderService,
  getOrderDetailsService,
  getAllOrderService,
  updateOrderStatusService,
  updateOrderItemsService,
  onQRScanService,
} from "../services/orderServices.js";
import Order from "../models/orderModel.js";
import { orderPublishService } from "../services/ablyService.js";
import { ORDER_STATUS } from "../utils/constant.js";
import { ClientError, NotFoundError } from "../utils/errorHandler.js";
import logger from "../utils/logger.js";

/**
 * Opens a table session for a QR customer and returns the menu.
 *
 * Public by necessity — the diner has no account. The response now carries a
 * `sessionToken` that every following customer request must present, which is
 * what scopes them to this one table.
 */
export const onQRScan = catchAsyncError(async (req, res) => {
  const data = await onQRScanService({ tableId: req.params.tableId });

  res.status(200).json({
    status: "success",
    message: "Table session started",
    data,
  });
});

export const getAllOrders = catchAsyncError(async (req, res) => {
  const orders = await getAllOrderService(req.hotelId, {
    status: req.query.status,
    tableId: req.query.tableId,
    activeOnly: req.query.activeOnly === "true",
  });

  res.status(200).json({
    status: "success",
    message: "Orders loaded",
    data: { orders },
  });
});

/**
 * Creates an order. Reached either by a diner holding a table session or by
 * staff working the floor.
 */
export const createOrder = catchAsyncError(async (req, res, next, session) => {
  const { tableId } = req.params;

  const { newOrder, newCustomer, table } = await addNewOrderService(
    { ...req.body, tableId, placedBy: req.user?._id },
    session
  );

  const order = await Order.findById(newOrder._id)
    .populate("customerId", "_id name")
    .populate("dishes.dishId")
    .populate("tableId", "_id sequence")
    .populate("hotelId", "_id name")
    .session(session);

  res.status(201).json({
    status: "success",
    message: "Order created",
    data: { order, customer: newCustomer, table },
  });
}, true);

export const updateOrderByOwner = catchAsyncError(
  async (req, res, next, session) => {
    const order = await updateOrderItemsService(
      req.params.orderId,
      req.hotelId,
      req.body.dishes,
      session
    );

    res.status(200).json({
      status: "success",
      message: "Order updated",
      data: { order },
    });
  },
  true
);

export const updateStatus = catchAsyncError(async (req, res, next, session) => {
  const data = await updateOrderStatusService(
    req.params.orderId,
    req.hotelId,
    req.params.status,
    session
  );

  res.status(200).json({
    status: "success",
    message: `Order marked ${req.params.status}`,
    data,
  });
}, true);

export const deleteOrder = catchAsyncError(async (req, res, next, session) => {
  const data = await deleteOrderService(
    req.params.orderId,
    req.hotelId,
    session
  );

  res.status(200).json({
    status: "success",
    message: "Order removed",
    data,
  });
}, true);

/**
 * Order detail.
 *
 * Was fully public — any order in the system, including the guest's name,
 * could be read by id. Staff are scoped to their own hotel; a diner may only
 * read an order on the table their session is bound to.
 */
export const getOrderDetails = catchAsyncError(async (req, res) => {
  const { orderId } = req.params;

  if (req.user) {
    const order = await getOrderDetailsService(orderId, req.hotelId);
    return res.status(200).json({
      status: "success",
      message: "Order loaded",
      data: { order },
    });
  }

  const order = await getOrderDetailsService(orderId);
  const orderTableId = (order.tableId?._id ?? order.tableId).toString();

  if (orderTableId !== req.customerSession?.tableId) {
    throw new NotFoundError("Order");
  }

  res.status(200).json({
    status: "success",
    message: "Order loaded",
    data: { order },
  });
});

/**
 * Confirms a draft order and pushes it to the kitchen board.
 *
 * Required a table session: this used to be open, so anyone could promote
 * another table's draft into a live kitchen order.
 */
export const publishOrder = catchAsyncError(async (req, res) => {
  const { orderId } = req.params;

  const order = await Order.findById(orderId)
    .populate("dishes.dishId", "_id name price")
    .populate("tableId", "_id sequence")
    .populate("hotelId", "_id name");

  if (!order) throw new NotFoundError("Order");

  const orderTableId = (order.tableId?._id ?? order.tableId).toString();

  // Staff are checked against their hotel; diners against their table.
  const permitted = req.user
    ? order.hotelId?._id?.toString() === req.hotelId?.toString()
    : orderTableId === req.customerSession?.tableId;

  if (!permitted) throw new NotFoundError("Order");

  if (order.status !== ORDER_STATUS.DRAFT) {
    throw new ClientError(
      "This order has already been sent to the kitchen.",
      409,
      "ORDER_ALREADY_PUBLISHED"
    );
  }

  order.status = ORDER_STATUS.PENDING;
  await order.save();

  // A realtime failure must not lose a confirmed order — the kitchen board
  // also polls, so log and carry on rather than rolling the order back.
  try {
    await orderPublishService(order);
  } catch (err) {
    logger.error(
      { err, orderId: order._id.toString() },
      "order confirmed but realtime publish failed"
    );
  }

  res.status(200).json({
    status: "success",
    message: "Order sent to the kitchen",
    data: { order },
  });
});
