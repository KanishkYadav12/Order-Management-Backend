import Bill from "../models/billModel.js";
import Order from "../models/orderModel.js"; // Import Order model
import Customer from "../models/customerModel.js"; // Import Customer model
import Table from "../models/tableModel.js";
import { ClientError, ServerError } from "../utils/errorHandler.js";
import sendEmail from "../utils/sendEmail.js";
import Offer from "../models/offerModel.js";

const checkGlobalOffer = async (globalOfferId, billAmount, session) => {
  try {
    // Find the offer by its ID
    const offer = await Offer.findById(globalOfferId).session(session);

    if (!offer) {
      throw new ClientError("Offer not found");
    }

    const currentDate = new Date(); // Get the current date and time
    // Check if the offer is valid based on its type, status, and dates
    if (offer.type !== "global") {
      throw new ClientError("Offer is not global");
    }

    if (billAmount < offer.appliedAbove) {
      throw new ClientError(
        `Offer is not applicable on amount less than ${offer.appliedAbove}!`
      );
    }

    if (offer.disable) {
      throw new ClientError("Offer is disabled");
    }

    // Check if the offer has started
    if (offer.startDate && currentDate < new Date(offer.startDate)) {
      throw new ClientError("Offer has not started yet");
    }

    // Check if the offer has expired
    if (offer.endDate && currentDate > new Date(offer.endDate)) {
      throw new ClientError("Offer has expired");
    }

    return offer;
  } catch (error) {
    throw error;
  }
};

export const updateBillService = async (billData, session) => {
  try {
    const { billId, customerName, customDiscount, customerEmail, globalOffer } =
      billData;
    // Step 1: Find the existing bill by billId
    const bill = await Bill.findById(billId)
      .populate("orderedItems.dishId")
      .populate("hotelId", "name address")
      .populate("tableId", "number sequence")
      .session(session);
    if (!bill) {
      throw new ServerError("Bill not found.");
    }
    // Step 2: Update the fields in the bill (except orderedItems)
    if (customerName) {
      bill.customerName = customerName.trim(); // Update customer name
    }
    if (customDiscount !== undefined) {
      if (
        typeof customDiscount !== "number" &&
        typeof customDiscount !== "string"
      ) {
        throw new Error(
          "Invalid input: customDiscount must be a number or a numeric string."
        );
      }
      const parsedDiscount =
        typeof customDiscount === "string"
          ? Number(customDiscount)
          : customDiscount;

      if (isNaN(parsedDiscount)) {
        throw new Error(
          "Invalid input: customDiscount must be a valid number."
        );
      }

      bill.customDiscount = parsedDiscount; // Update customDiscount
      bill.totalDiscount += parsedDiscount;
      bill.finalAmount = bill.totalAmount - bill.totalDiscount;
    }

    if (customerEmail) {
      bill.customerEmail = customerEmail;
    }

    if (globalOffer) {
      if (bill.globalOffer != globalOffer) {
        const offer = await checkGlobalOffer(
          globalOffer,
          bill.totalAmount,
          session
        );
        if (!offer) throw new ServerError("Offer not found");
        if (bill.globalOffer) {
          const oldOffer = await Offer.findById(bill.globalOffer).session(
            session
          );
          if (!oldOffer) throw new ServerError("Old Offer not found");
          if (oldOffer.discountType === "amount") {
            bill.totalDiscount -= oldOffer.value;
          } else if (oldOffer.discountType === "percent") {
            const discountAmount = (oldOffer.value / 100) * bill.totalAmount;
            bill.totalDiscount -= discountAmount;
          }
        }
        if (offer.discountType === "amount") {
          bill.totalDiscount += offer.value;
        } else if (offer.discountType === "percent") {
          const discountAmount = (offer.value / 100) * bill.totalAmount;
          bill.totalDiscount += discountAmount;
        }
        bill.finalAmount = bill.totalAmount - bill.totalDiscount;
        bill.globalOffer = globalOffer;
      }
    }
    await bill.save({ session });

    return bill;
  } catch (error) {
    console.error("Error while updating bill:", error.message);
    throw error; // Handle error
  }
};

export const billPayService = async (billId, data, session) => {
  try {
    // Step 1: Find the existing bill by billId
    const bill = await Bill.findById(billId)
      .populate("orderedItems.dishId")
      .populate("hotelId", "name address")
      .populate("tableId", "number sequence")
      .session(session);

    if (!bill) {
      throw new ServerError("Bill not found.");
    }
    const tableId = bill.tableId;
    bill.status = "paid";
    bill.customerId = null;
    bill.globalOffer = null;
    if (data?.customerEmail) bill.customerEmail = data.customerEmail;
    await bill.save({ session });

    // Delete all orders related to this tableId
    const updatedTable = await Table.findByIdAndUpdate(
      tableId,
      { status: "free", customer: null },
      { new: true, session }
    );
    const orders = await Order.find({ tableId }).session(session);

    const orderIds = orders.map((order) => order._id);

    await Order.deleteMany({ tableId }).session(session); // Delete all orders for the tableId
    // console.log("orderIds : ", orderIds);

    await Customer.deleteOne({ tableId }).session(session); // Delete customer for the tableId
    return { bill, table: updatedTable, orders: orderIds };
  } catch (error) {
    throw error;
  }
};

export const sendBillToMailService = async (billId, mailId) => {
    if (!billId || !mailId) {
      throw new ServerError("Bill ID and mail ID are required.");
    }
    const billDetails = await Bill.findById(billId)
      .populate("orderedItems.dishId", "name price")
      .populate("hotelId", "name address")
      .populate("tableId", "number sequence");
    
    if(billDetails.status != 'paid') throw new ClientError("Bill is not paid yet!");

    if (!billDetails) {
      throw new ServerError("Bill not found.");
    }

    const orderedItemsRows = generateOrderedItemsRows(billDetails.orderedItems);

    const billHTML = generateBillHTML(billDetails, orderedItemsRows);

    await sendEmail(mailId, "Bill Details", billHTML);
    billDetails.customerEmail = mailId;
    billDetails.save();
    return { message: "Bill sent to mail successfully.", billDetails };
};

// Function to generate the ordered items table rows
const generateOrderedItemsRows = (orderedItems) => {
  return orderedItems
    .map(
      (item) => `
        <tr>
          <td>${item.dishId?.name || "Unknown Dish"}</td>
          <td>${item.quantity || 0}</td>
          <td>₹${item.dishId?.price.toFixed(2) || "0.00"}</td>
          <td>₹${(item.quantity * item.dishId?.price || 0).toFixed(2)}</td>
        </tr>`
    )
    .join("");
};

// Function to generate the complete bill HTML
const generateBillHTML = (billDetails, orderedItemsRows) => {
  const {
    _id: id,
    customerName,
    tableId,
    hotelId,
    totalAmount,
    totalDiscount,
    customDiscount,
    finalAmount,
  } = billDetails;

  return `
        <html>
        <head>
          <style>
            body {
          font-family: Arial, sans-serif;
          margin: 20px;
        }
        .bill-container {
            max-width: 600px;
          margin: 0 auto;
          border: 1px solid #ddd;
          border-radius: 5px;
          padding: 20px;
          background-color: #f9f9f9;
        }
        .bill-header {
          text-align: center;
          margin-bottom: 20px;
        }
        .bill-header h1 {
            margin: 0;
        }
        .bill-details, .ordered-items {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
          }
          .bill-details th, .bill-details td, .ordered-items th, .ordered-items td {
          border: 1px solid #ddd;
          padding: 8px;
          text-align: left;
        }
        .bill-details th, .ordered-items th {
          background-color: #f2f2f2;
        }
        .total-row {
            font-weight: bold;
        }
        .footer {
            text-align: center;
            margin-top: 20px;
            font-size: 0.9em;
          color: #555;
        }
      </style>
    </head>
    <body>
      <div class="bill-container">
        <div class="bill-header">
          <h1>${hotelId?.name || "Hotel-Name"}</h1>
        </div>
        <table class="bill-details">
          <tr>
            <th>Bill ID</th>
            <td>${id}</td>
          </tr>
          <tr>
            <th>Customer Name</th>
            <td>${customerName || "N/A"}</td>
          </tr>
          <tr>
            <th>Table Number</th>
            <td>${tableId?.sequence || "N/A"}</td>
          </tr>
        </table>
        <h3>Ordered Items</h3>
        <table class="ordered-items">
          <thead>
            <tr>
              <th>Dish</th>
              <th>Quantity</th>
              <th>Price</th>
              <th>Total</th>
            </tr>
          </thead>
          <tbody>
            ${orderedItemsRows}
            <tr class="total-row">
              <td colspan="3">Total Amount</td>
              <td>₹${totalAmount.toFixed(2)}</td>
            </tr>
            <tr class="total-row">
              <td colspan="3">Total Discount</td>
              <td>-₹${totalDiscount.toFixed(2)}</td>
            </tr>
            <tr class="total-row">
              <td colspan="3">Custom Discount</td>
              <td>-₹${customDiscount.toFixed(2)}</td>
            </tr>
            <tr class="total-row">
              <td colspan="3">Final Amount</td>
              <td>₹${finalAmount.toFixed(2)}</td>
            </tr>
          </tbody>
        </table>
        <div class="footer">
          Thank you for dining with us!
        </div>
      </div>
    </body>
    </html>
  `;
};

// //modern one -- does not work properly on mobiles par desktops pe achha dikh rha tha :(
// const generateBillHTML = (billDetails, orderedItemsRows) => {
//   const {
//     _id: id,
//     customerName,
//     tableId,
//     hotelId,
//     totalAmount,
//     totalDiscount,
//     customDiscount,
//     finalAmount,
//   } = billDetails;

//   return `
//     <html>
//     <head>
//       <style>
//         * {
//           margin: 0;
//           padding: 0;
//           box-sizing: border-box;
//         }
//         body {
//           font-family: 'Arial', sans-serif;
//           background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
//           min-height: 100vh;
//           display: flex;
//           align-items: center;
//           justify-content: center;
//           padding: 20px;
//         }
//         .bill-container {
//           background-color: #ffffff;
//           border-radius: 10px;
//           box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
//           overflow: hidden;
//           width: 100%;
//           max-width: 700px;
//         }
//         .bill-header {
//           background: linear-gradient(to right, #4a90e2, #7e57c2);
//           color: #ffffff;
//           padding: 25px;
//           text-align: center;
//         }
//         .bill-header h1 {
//           font-size: 28px;
//           margin-bottom: 8px;
//         }
//         .bill-header p {
//           font-size: 16px;
//           opacity: 0.9;
//         }
//         .bill-info {
//           display: flex;
//           justify-content: space-between;
//           gap: 20px;
//           padding: 25px;
//           background-color: #f8f9fa;
//           border-bottom: 1px solid #e9ecef;
//         }
//         .bill-info div {
//           font-size: 16px;
//           line-height: 1.8;
//         }
//         .bill-info span {
//           font-weight: bold;
//           color: #333;
//         }
//         .order-details {
//           padding: 25px;
//         }
//         .order-details h2 {
//           font-size: 22px;
//           margin-bottom: 20px;
//           font-weight: bold;
//           color: #333;
//         }
//         table {
//           width: 100%;
//           border-collapse: collapse;
//         }
//         th, td {
//           padding: 14px 18px;
//           text-align: left;
//           border-bottom: 1px solid #e9ecef;
//         }
//         th {
//           background-color: #f8f9fa;
//           font-weight: bold;
//           color: #495057;
//           text-transform: uppercase;
//           font-size: 14px;
//         }
//         td {
//           font-size: 16px;
//           color: #555;
//         }
//         .total-section {
//           background-color: #f8f9fa;
//           padding: 25px;
//         }
//         .total-row {
//           display: flex;
//           justify-content: space-between;
//           margin-bottom: 12px;
//         }
//         .total-row span:last-child {
//           text-align: right;
//           flex-grow: 1;
//         }
//         .total-row.final {
//           font-weight: bold;
//           font-size: 20px;
//           border-top: 2px solid #dee2e6;
//           padding-top: 12px;
//           margin-top: 12px;
//         }
//         .discount {
//           color: #28a745;
//         }
//         .bill-footer {
//           text-align: center;
//           padding: 25px;
//           background-color: #f8f9fa;
//           border-top: 1px solid #e9ecef;
//           font-size: 16px;
//           color: #6c757d;
//           line-height: 1.8;
//         }
//       </style>
//     </head>
//     <body>
//       <div class="bill-container">
//         <div class="bill-header">
//           <h1>${hotelId?.name || "Luxury Hotel"}</h1>
//           <p>${hotelId?.address || "123 Main St, City, Country"}</p>
//         </div>
//         <div class="bill-info">
//           <div>
//             <p>Bill ID: <span>${id}</span></p>
//             <p>Date: <span>${new Date().toLocaleDateString()}</span></p>
//           </div>
//           <div>
//             <p>Customer: <span>${customerName || "N/A"}</span></p>
//             <p>Table: <span>${tableId?.sequence || "N/A"}</span></p>
//           </div>
//         </div>
//         <div class="order-details">
//           <h2>Order Details</h2>
//           <table>
//             <thead>
//               <tr>
//                 <th>Item</th>
//                 <th>Qty</th>
//                 <th>Price</th>
//                 <th>Total</th>
//               </tr>
//             </thead>
//             <tbody>
//               ${orderedItemsRows}
//             </tbody>
//           </table>
//         </div>
//         <div class="total-section">
//           <div class="total-row">
//             <span>Subtotal</span>
//             <span>₹${totalAmount.toFixed(2)}</span>
//           </div>
//           <div class="total-row">
//             <span>Total Discount</span>
//             <span class="discount">-₹${totalDiscount.toFixed(2)}</span>
//           </div>
//           <div class="total-row">
//             <span>Custom Discount</span>
//             <span class="discount">-₹${customDiscount.toFixed(2)}</span>
//           </div>
//           <div class="total-row final">
//             <span>Total</span>
//             <span>₹${finalAmount.toFixed(2)}</span>
//           </div>
//         </div>
//         <div class="bill-footer">
//           <p>Thank you for dining with us!</p>
//           <p>We hope to see you again soon.</p>
//         </div>
//       </div>
//     </body>
//     </html>
//   `;
// };
