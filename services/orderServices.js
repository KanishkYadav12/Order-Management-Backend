import Order from "../models/orderModel.js";
import Customer from "../models/customerModel.js";
import { Category, Dish } from "../models/dishModel.js";
import Table from "../models/tableModel.js";
import { ClientError, ServerError } from "../utils/errorHandler.js";
import mongoose from "mongoose";
import Bill from "../models/billModel.js";

export const onQRScanService = async ({ tableId }) => {
  const table = await Table.findById(tableId);

  if (!table) {
    throw new ClientError("Table not found!");
  }

  const hotelId = table.hotelId;

  const customer = await Customer.findOne({ tableId, hotelId });

  const orders = await Order.find({ tableId, hotelId });
  if (
    (orders.length > 0 && !customer) ||
    (orders.length > 0 && orders[0].customerId != customer._id.toString())
  ) {
    throw new ServerError("Orders are available while customer is not");
  }

  // for creating menu
  const dishes = await Dish.find({ hotelId });
  const categories = await Category.find({ hotelId });

  const data = {
    table: table,
    customerName: customer,
    existingOrders: orders,
    menu: {
      categories,
      dishes,
    },
  };

  return data;
};

export const addNewOrderService = async (orderData, session) => {
  console.log("Order data----------", orderData);
  const { customerName, tableId, dishes, note, status } = orderData;

  // Validate table existence
  const table = await Table.findById(tableId);
  if (!table) {
      throw new ClientError("Table not found!");
  }
  const hotelId = table.hotelId;

  let customer = await Customer.findOne({ tableId, hotelId }).session(session);
  let newCustomer = null;
  let updatedTable = null;
  let isFirstOrder = false;

  if (!customer) {
      console.log("Customer not available");
      customer = new Customer({
          hotelId,
          tableId,
          name: customerName,
      });
      newCustomer = customer;
      await customer.save({ session });
      updatedTable = await Table.findByIdAndUpdate(
          tableId,
          { status: "occupied", customer: customer._id },
          { new: true, session }
      );
      isFirstOrder = true;
  }

  // Validate dishes for "outOfStock" status
  console.log("Dishes in new order ", dishes);

  const dishIds = dishes.map(dish => dish.dishId); // Extract dish IDs from the input
  const foundDishes = await Dish.find({ _id: { $in: dishIds }, hotelId }); // Find dishes by IDs and hotelId

  // Check if all dishes exist
  const missingDishIds = dishIds.filter(
      id => !foundDishes.some(dish => dish._id.toString() === id)
  );
  foundDishes.forEach((dish)=>{
    if(dish.isDeleted == true) missingDishIds.push(dish?._id?.toString())
  })

  // here you can see in out dish model there is a field idDeleted if it is true then even it will be considered as missing dish so please handle this case also

  if (missingDishIds.length > 0) {
      throw new ServerError(`The following dishes were not found: ${missingDishIds.join(", ")}`);
  }

  // Check for out-of-stock dishes
  const outOfStockDishes = foundDishes.filter(dish => dish.outOfStock);
  if (outOfStockDishes.length > 0) {
      const outOfStockNames = outOfStockDishes.map(dish => dish.name).join(", ");
      throw new ServerError(`The following dishes are out of stock: ${outOfStockNames}`);
  }

  const newOrder = new Order({
      customerId: customer._id,
      dishes: dishes.map(dish => ({
          dishId: new mongoose.Types.ObjectId(dish.dishId),
          quantity: dish.quantity,
          notes: dish.notes,
      })),
      status: status || "draft",
      tableId,
      hotelId,
      note: note || "",
      isFirstOrder: isFirstOrder,
  });

  console.log("New order ", newOrder);
  await newOrder.save({ session });

  return { newOrder, newCustomer, table: updatedTable };
};


// only for hotel owner
export const deleteOrderService = async (orderId, session) => {
  try {
    const order = await Order.findById(orderId).session(session);

    if (!order) {
      throw new ClientError("Order not found");
    }

    const tableId = order.tableId;
    await Order.findByIdAndDelete(orderId, { session });

    // Find remaining orders for the table
    const remainingOrders = await Order.find({ tableId }).session(session);

    const customer = await Customer.findOne({ tableId }).session(session);
    let updatedTable = null;
    if (!remainingOrders || remainingOrders.length === 0) {
      // No remaining orders, free the table, delete customer and bill
      updatedTable = await Table.findByIdAndUpdate(
        tableId,
        { status: "free", customer: null },
        { new: true, session }
      );

      if (customer) {
        await customer.deleteOne({ session });
        const bill = await Bill.findOne({
          tableId,
          customerId: customer._id,
        }).session(session);
        if (bill) await bill.deleteOne({ session });
      }
    } else {
      // Remaining orders, check if all are "draft"
      const allDraft = remainingOrders.every(
        (order) => order.status === "draft"
      );

      if (allDraft) {
        // If all orders are "draft", free the table and delete the bill (but not the customer)
        updatedTable = await Table.findByIdAndUpdate(
          tableId,
          { status: "free", customer: null },
          { new: true, session }
        );

        const bill = await Bill.findOne({
          tableId,
          customerId: customer._id,
        }).session(session);
        if (bill) await bill.deleteOne({ session });
      }
    }

    return { order, table: updatedTable };
  } catch (error) {
    throw new ServerError(
      error.message || "An error occurred while deleting the order"
    );
  }
};

export const getOrderDetailsService = async (orderId) => {
  try {
    const order = await Order.findById(orderId)
      .populate("customerId", "_id name")
      .populate("dishes.dishId")
      .populate("tableId", "_id sequence capacity position")
      .populate("hotelId", "_id name");

    console.log("order", order);
    if (!order) {
      throw new ClientError("Order not found!");
    }

    return order;
  } catch (error) {
    console.error("Error in getOrderDetailsService:", error);
    throw new ServerError(error.message);
  }
};

export const getAllOrderService = async (hotelId) => {
  try {
    const orders = await Order.find({ hotelId: hotelId })
      .populate("customerId", "_id name")
      .populate("dishes.dishId")
      .populate("tableId", "_id sequence")
      .populate("hotelId", "_id name");

    if (!orders) {
      throw new ClientError("Order not found");
    }

    return orders;
  } catch (error) {
    console.error("Error in getOrderDetailsService:", error);
    throw new ServerError(error.message);
  }
};

export const updateOrderStatusService = async (orderId, status, session) => {
  try {
    console.log("Order id ---> 1", orderId, status);
    const updatedOrder = await Order.findByIdAndUpdate(
      orderId,
      { status: status },
      { new: true }
    )
      .populate("customerId", "_id name")
      .populate("dishes.dishId", "_id name price")
      .populate("tableId", "_id number sequence")
      .populate("hotelId", "_id name");

    const tableId = updatedOrder.tableId._id;
    const customerId = updatedOrder.customerId._id;
    let updatedTable = null;

    if (status && status !== "draft") {
      updatedTable = await Table.findByIdAndUpdate(
        tableId,
        { status: "occupied", customer: customerId },
        { new: true, session }
      );
    }

    // If status is "draft", check the remaining orders for the table
    if (status === "draft") {
      const remainingOrders = await Order.find({
        tableId,
        status: { $ne: "draft" },
      }).session(session);
      if (remainingOrders.length === 0) {
        // If no remaining orders are not "draft", free the table and delete the bill
        updatedTable = await Table.findByIdAndUpdate(
          tableId,
          { status: "free", customer: null },
          { new: true, session }
        );
        const bill = await Bill.findOne({
          tableId,
          customerId,
        }).session(session);
        if (bill) await bill.deleteOne({ session });
      }
    }

    return { order: updatedOrder, table: updatedTable };
  } catch (error) {
    throw new ServerError(
      error.message || "An error occurred while updating the order status"
    );
  }
};
