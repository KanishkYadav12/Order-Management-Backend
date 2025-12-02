import { catchAsyncError } from "../middlewares/catchAsyncError.js";
import { Dish } from "../models/dishModel.js";
import offerModel from "../models/offerModel.js";
import orderModel from "../models/orderModel.js";
import tableModel from "../models/tableModel.js";
import { deleteOrderPublishService } from "../services/ablyService.js";
import { getAllCategoriesService } from "../services/categoryServices.js";
import { deleteOrderService } from "../services/orderServices.js";
import { ClientError, ServerError } from "../utils/errorHandler.js";

export const getHotelDishes = catchAsyncError(async (req, res) => {
  const hotelId = req.params.hotelId;
  const dishes = await Dish.find({
    hotelId: hotelId,
    isDeleted: false,
  }).populate("ingredients category offer");
  return res.send({
    status: "success",
    message: "Customer dishes fetched successfully",
    data: { dishes: dishes },
  });
});

export const getHotelCategories = catchAsyncError(async (req, res) => {
  const hotelId = req.params.hotelId;
  const categories = await getAllCategoriesService(hotelId);
  return res.send({
    status: "success",
    message: "Customer categories fetched successfully",
    data: { categories: categories },
  });
});

export const getHotelTable = catchAsyncError(async (req, res) => {
  const tableId = req.params.tableId;
  const table = await tableModel.findById(tableId).populate("customer");
  if (!table) throw new ServerError("table not found");
  return res.send({
    status: "success",
    message: "Customer Table fetched successfully",
    data: { table: table },
  });
});

export const getHotelOffers = catchAsyncError(async (req, res) => {
  const hotelId = req.params.hotelId;
  const offers = await offerModel
    .find({ hotelId: hotelId })
    .populate("appliedOn");

  res.status(201).json({
    status: "success",
    message: "All customer Offers fetched successfully",
    data: { offers },
  });
});

export const getTableOrders = catchAsyncError(async (req, res) => {
  const tableId = req.params.tableId;
  const {customerId} = req.query;
  if(!tableId) throw new ClientError("Required", "table id is required to get table orders");
  const table = await tableModel.findById(tableId);
  if(!table) throw new ClientError("NotFound", "table id is invalid");
  
  let orders = await orderModel
    .find({ tableId: tableId })
    .populate("customerId", "_id name")
    .populate("dishes.dishId")
    .populate("tableId", "_id sequence")
    .populate("hotelId", "_id name");
  if (!orders || !customerId || !table.customer || table.customer.toString() != customerId ){
    orders = [];
  }

  res.status(201).json({
    status: "success",
    message: "All customer Orders fetched successfully",
    data: { orders },
  });

  return orders;
});

export const deleteDraftOrders = catchAsyncError(
  async (req, res, next, session) => {
    const { orderId } = req.params;
    if (!orderId) {
      throw new ClientError("Please provide sufficient data to delete order");
    }
    const order = await orderModel.findById(orderId);
    if (!order) throw new ServerError("Order not found!");
    if (order.status != "draft")
      throw new ServerError(
        "you can not delete this order, please contact to staff"
      );
    const data = await deleteOrderService(orderId, session);
    await deleteOrderPublishService(order);

    res.status(201).json({
      status: "success",
      message: "Order deleted successfully",
      data,
    });
  },
  true
);
