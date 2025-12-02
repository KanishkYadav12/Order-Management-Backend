import { getTableByIdService, getTablesService, createTableService, deleteTableService, updateTableService, getOrdersByTableService, generateTableBillService } from '../services/tableService.js';
import { ClientError, ServerError } from '../utils/errorHandler.js'; // Import the custom error classes
import { catchAsyncError } from '../middlewares/catchAsyncError.js';
import Order from '../models/orderModel.js';
import Customer from '../models/customerModel.js';

export const getTableById = catchAsyncError(async (req, res) => {
    console.log("get table ")
    const tableId = req.params.id;
    console.log("tabeId ::: ", tableId)
    const table = await getTableByIdService(tableId);
    if (!table) {throw new ClientError("table not found")}
    console.log("table :::", table)
    res.status(200).json({
        status: "success",
        message: 'Table fetched successfully',
        data: { table },
    });
});

export const getTables = catchAsyncError(async (req, res) => {
    const tables = await getTablesService(req.user);
    res.status(200).json({
        status: "success",
        message: 'All Tables fetched successfully',
        data: { tables },
    });
});

export const createTable = catchAsyncError(async (req, res) => {
    const tableData = req.body;
    const table = await createTableService(req.user, tableData);
    res.status(201).json({
        status: "success",
        message: 'Table created successfully',
        data: { table },
    });
});

export const updateTable = catchAsyncError(async (req, res) => {
    const tableId = req.params.tableId;
    const tableData = req.body;
    const table = await updateTableService(tableId, tableData);
    res.status(200).json({
        status: "success",
        message: 'Table updated successfully',
        data: { table },
    });
});

export const deleteTable = catchAsyncError(async (req, res) => {
    const tableId = req.params.id;
    const table = await deleteTableService(tableId);
    console.log("deteled table ---", table)
    res.status(200).json({
        status: "success",
        message: 'Table deleted successfully',
        data : {
            table : table
        }
    });
});


// export const getAllTablesOfHotel = catchAsyncError(async (req, res) => {
//     const tables = await getAllTablesOfHotelService(req.user);
//     res.status(200).json({
//         status : "success",
//         message: 'Tables fetched successfully',
//         data: { tables },
//     });
// });

export const getOrdersByTable = catchAsyncError(async (req, res, next) => {
    const { tableId } = req.params;
    console.log('req, to get orders of table')

    if (!tableId) {
        throw new ClientError("Please provide table id to get orders");
    }

    const orders = await getOrdersByTableService(tableId);

    res.status(201).json({
        success: true,
        message: "Orders fetched successfully",
        data: { orders }
    })
})


export const generateTableBill = catchAsyncError(async (req, res, next, session) => {
    const { tableId } = req.params;
    if (!tableId) {
        throw new ClientError("Please provide table id to generate bill!");
    }
    const bill = await generateTableBillService(tableId, session);

    res.status(201).json({
        status: "success",
        message: "Bill generated successfully",
        data: { bill }
    })

}, true)



export const getCustomerDetails = catchAsyncError(async (req, res, next) => {
    const { tableId } = req.params;
    if (!tableId) {
        throw new ClientError("Please provide table id to get customer details!");
    }
    const customer = await Customer.findOne({ tableId });

    res.status(201).json({
        status: "success",
        message: "Customer fetched successfully",
        data: { customer }
    })
})