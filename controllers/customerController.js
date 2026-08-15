import { catchAsyncError } from "../middlewares/catchAsyncError.js";
import { Dish } from "../models/dishModel.js";
import Offer from "../models/offerModel.js";
import Order from "../models/orderModel.js";
import Table from "../models/tableModel.js";
import Hotel from "../models/hotelModel.js";
import { deleteOrderPublishService } from "../services/ablyService.js";
import { getAllCategoriesService } from "../services/categoryServices.js";
import { deleteOrderService } from "../services/orderServices.js";
import { ORDER_STATUS } from "../utils/constant.js";
import { ClientError, NotFoundError } from "../utils/errorHandler.js";
import logger from "../utils/logger.js";

/**
 * The customer-facing menu API.
 *
 * These endpoints back the QR app, where the diner has no account. What they
 * return is menu data a guest sitting in the restaurant can already see, so
 * the browse routes stay open — but anything tied to a specific sitting now
 * requires the table session issued at QR scan.
 */

const activeHotel = async (hotelId) => {
  const hotel = await Hotel.findById(hotelId).select(
    "name logo banner description billing serviceHours isActive"
  );
  if (!hotel || !hotel.isActive) throw new NotFoundError("Restaurant");
  return hotel;
};

export const getHotelDishes = catchAsyncError(async (req, res) => {
  const { hotelId } = req.params;
  await activeHotel(hotelId);

  const dishes = await Dish.find({
    hotelId,
    isDeleted: false,
  })
    .populate("ingredients category offer")
    // Cost and recipe are internal; a diner has no business seeing them.
    .select("-recipe -taxRatePercent");

  res.status(200).json({
    status: "success",
    message: "Menu loaded",
    data: { dishes },
  });
});

export const getHotelCategories = catchAsyncError(async (req, res) => {
  const { hotelId } = req.params;
  await activeHotel(hotelId);

  const categories = await getAllCategoriesService(hotelId);

  res.status(200).json({
    status: "success",
    message: "Categories loaded",
    data: { categories },
  });
});

export const getHotelOffers = catchAsyncError(async (req, res) => {
  const { hotelId } = req.params;
  await activeHotel(hotelId);

  const now = new Date();
  const offers = await Offer.find({
    hotelId,
    disable: false,
    $and: [
      { $or: [{ startDate: null }, { startDate: { $lte: now } }] },
      { $or: [{ endDate: null }, { endDate: { $gte: now } }] },
    ],
  }).populate("appliedOn", "_id name price");

  res.status(200).json({
    status: "success",
    message: "Offers loaded",
    data: { offers },
  });
});

/** Table details for the QR header. Requires a session for that table. */
export const getHotelTable = catchAsyncError(async (req, res) => {
  const { tableId } = req.params;

  const table = await Table.findOne({ _id: tableId, isDeleted: false })
    .select("_id sequence capacity status hotelId")
    .populate("hotelId", "name logo");

  if (!table) throw new NotFoundError("Table");

  res.status(200).json({
    status: "success",
    message: "Table loaded",
    data: { table },
  });
});

/**
 * The diner's own orders for this sitting.
 *
 * Scoped by the signed table session rather than by a `customerId` supplied
 * in the query string, which the caller could simply change.
 */
export const getTableOrders = catchAsyncError(async (req, res) => {
  const { tableId } = req.params;
  const { customerId } = req.customerSession;

  const orders = customerId
    ? await Order.find({ tableId, customerId })
        .populate("customerId", "_id name")
        .populate("dishes.dishId")
        .populate("tableId", "_id sequence")
        .populate("hotelId", "_id name")
        .sort({ createdAt: 1 })
    : [];

  res.status(200).json({
    status: "success",
    message: "Orders loaded",
    data: { orders },
  });
});

/** A diner may cancel their own order only while it is still a draft. */
export const deleteDraftOrders = catchAsyncError(
  async (req, res, next, session) => {
    const { orderId } = req.params;

    const order = await Order.findById(orderId).session(session);
    if (!order) throw new NotFoundError("Order");

    if (order.tableId.toString() !== req.customerSession.tableId) {
      throw new NotFoundError("Order");
    }

    if (order.status !== ORDER_STATUS.DRAFT) {
      throw new ClientError(
        "This order is already with the kitchen. Please ask a member of staff.",
        409,
        "ORDER_NOT_DRAFT"
      );
    }

    const data = await deleteOrderService(orderId, order.hotelId, session);

    try {
      await deleteOrderPublishService(order);
    } catch (err) {
      logger.error({ err, orderId }, "order deleted but realtime publish failed");
    }

    res.status(200).json({
      status: "success",
      message: "Order removed",
      data,
    });
  },
  true
);
