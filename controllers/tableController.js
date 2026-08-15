import { catchAsyncError } from "../middlewares/catchAsyncError.js";
import {
  getTableByIdService,
  getTablesService,
  createTableService,
  deleteTableService,
  updateTableService,
  getOrdersByTableService,
  getCustomerForTableService,
} from "../services/tableService.js";
import { generateTableBillService } from "../services/billServices.js";

export const getTableById = catchAsyncError(async (req, res) => {
  const table = await getTableByIdService(
    req.params.tableId ?? req.params.id,
    req.hotelId
  );

  res.status(200).json({
    status: "success",
    message: "Table loaded",
    data: { table },
  });
});

export const getTables = catchAsyncError(async (req, res) => {
  const tables = await getTablesService(req.hotelId, {
    status: req.query.status,
  });

  res.status(200).json({
    status: "success",
    message: "Tables loaded",
    data: { tables },
  });
});

export const createTable = catchAsyncError(async (req, res) => {
  const table = await createTableService(req.hotelId, req.body);

  res.status(201).json({
    status: "success",
    message: "Table created",
    data: { table },
  });
});

export const updateTable = catchAsyncError(async (req, res) => {
  const table = await updateTableService(
    req.params.tableId,
    req.hotelId,
    req.body
  );

  res.status(200).json({
    status: "success",
    message: "Table updated",
    data: { table },
  });
});

export const deleteTable = catchAsyncError(async (req, res) => {
  const table = await deleteTableService(
    req.params.tableId ?? req.params.id,
    req.hotelId
  );

  res.status(200).json({
    status: "success",
    message: "Table removed",
    data: { table },
  });
});

export const getOrdersByTable = catchAsyncError(async (req, res) => {
  const orders = await getOrdersByTableService(
    req.params.tableId,
    req.hotelId
  );

  res.status(200).json({
    status: "success",
    message: "Orders loaded",
    data: { orders },
  });
});

export const generateTableBill = catchAsyncError(
  async (req, res, next, session) => {
    const bill = await generateTableBillService(
      req.params.tableId,
      req.hotelId,
      session
    );

    res.status(200).json({
      status: "success",
      message: "Bill generated",
      data: { bill },
    });
  },
  true
);

export const getCustomerDetails = catchAsyncError(async (req, res) => {
  const customer = await getCustomerForTableService(
    req.params.tableId,
    req.hotelId
  );

  res.status(200).json({
    status: "success",
    message: "Customer loaded",
    data: { customer },
  });
});
