import Table from "../models/tableModel.js";
import Order from "../models/orderModel.js";
import Customer from "../models/customerModel.js";
import { TABLE_STATUS } from "../utils/constant.js";
import {
  ClientError,
  NotFoundError,
  ConflictError,
} from "../utils/errorHandler.js";

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
 * Every lookup is `{ _id, hotelId }`, never `findById`.
 *
 * The read, update and delete routes previously had no ownership check at all,
 * so any signed-in owner could rename or delete another restaurant's tables
 * just by knowing an id.
 */
export const getTableByIdService = async (tableId, hotelId) => {
  assertScope(hotelId);

  const table = await Table.findOne({ _id: tableId, hotelId, isDeleted: false })
    .populate("hotelId", "name")
    .populate("customer");

  if (!table) throw new NotFoundError("Table");
  return table;
};

export const getTablesService = async (hotelId, options = {}) => {
  assertScope(hotelId);

  const filter = { hotelId, isDeleted: false };
  if (options.status) filter.status = options.status;

  return Table.find(filter)
    .populate("hotelId", "name")
    .populate("customer")
    .sort({ sequence: 1 });
};

export const createTableService = async (hotelId, tableData) => {
  assertScope(hotelId);

  try {
    return await Table.create({ ...tableData, hotelId });
  } catch (err) {
    if (err.code === 11000) {
      throw new ConflictError(
        `Table ${tableData.sequence} already exists in this restaurant.`
      );
    }
    throw err;
  }
};

/**
 * Occupied tables can still have their capacity or position corrected; only
 * the table number is frozen, because it is what the printed QR code encodes.
 */
export const updateTableService = async (tableId, hotelId, tableData) => {
  assertScope(hotelId);

  const table = await Table.findOne({ _id: tableId, hotelId, isDeleted: false });
  if (!table) throw new NotFoundError("Table");

  const { hotelId: _ignored, _id: _ignoredId, customer, ...safeData } = tableData;

  if (
    safeData.sequence !== undefined &&
    safeData.sequence !== table.sequence &&
    table.status !== TABLE_STATUS.FREE
  ) {
    throw new ClientError(
      "You can't renumber a table while it's in use.",
      409,
      "TABLE_IN_USE"
    );
  }

  Object.assign(table, safeData);

  try {
    await table.save();
  } catch (err) {
    if (err.code === 11000) {
      throw new ConflictError(
        `Table ${safeData.sequence} already exists in this restaurant.`
      );
    }
    throw err;
  }

  return table;
};

export const deleteTableService = async (tableId, hotelId) => {
  assertScope(hotelId);

  const table = await Table.findOne({ _id: tableId, hotelId, isDeleted: false });
  if (!table) throw new NotFoundError("Table");

  if (table.status !== TABLE_STATUS.FREE) {
    throw new ClientError(
      "Settle this table before removing it.",
      409,
      "TABLE_IN_USE"
    );
  }

  const liveOrders = await Order.countDocuments({
    tableId,
    status: { $nin: ["completed", "cancelled"] },
  });
  if (liveOrders > 0) {
    throw new ClientError(
      "This table still has open orders.",
      409,
      "TABLE_HAS_ORDERS"
    );
  }

  // Soft delete keeps historical bills and orders resolvable.
  table.isDeleted = true;
  await table.save();
  return table;
};

export const getOrdersByTableService = async (tableId, hotelId) => {
  assertScope(hotelId);

  const table = await Table.exists({ _id: tableId, hotelId });
  if (!table) throw new NotFoundError("Table");

  return Order.find({ tableId, hotelId })
    .populate("customerId", "_id name")
    .populate("dishes.dishId")
    .populate("tableId", "_id sequence")
    .populate("hotelId", "_id name")
    .sort({ createdAt: -1 });
};

export const getCustomerForTableService = async (tableId, hotelId) => {
  assertScope(hotelId);
  return Customer.findOne({ tableId, hotelId });
};

/** Marks a table free and detaches its customer. Used after payment. */
export const releaseTableService = async (tableId, hotelId, session) =>
  Table.findOneAndUpdate(
    { _id: tableId, hotelId },
    {
      status: TABLE_STATUS.FREE,
      customer: null,
      covers: null,
      occupiedAt: null,
    },
    { new: true, session }
  );

/** Seats a party: marks occupied and starts the turn-time clock. */
export const occupyTableService = async (
  tableId,
  hotelId,
  customerId,
  session
) =>
  Table.findOneAndUpdate(
    { _id: tableId, hotelId },
    {
      status: TABLE_STATUS.OCCUPIED,
      customer: customerId,
      occupiedAt: new Date(),
    },
    { new: true, session }
  );
