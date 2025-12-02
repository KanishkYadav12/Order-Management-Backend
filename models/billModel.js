import mongoose from "mongoose";

const billSchema = new mongoose.Schema(
  {
    customerId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Customer",
    },

    customerName: {
      type: String,
      required: true,
    },
    customerEmail: {
      type: String,
    },
    orderedItems: [
      {
        dishId: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "Dish",
        },
        quantity: {
          type: Number,
          required: true,
        },
      },
    ],
    globalOffer: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Offer",
    },
    totalAmount: {
      type: Number,
      required: true,
    },
    totalDiscount: {
      type: Number,
      default: 0,
    },
    customDiscount: {
      type: Number,
      default: 0,
    },
    status: {
      type: String,
      enum: ["paid", "unpaid", "payLater"],
      default: "unpaid",
    }, // After discount
    finalAmount: {
      type: Number,
      required: true,
    },
    hotelId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Hotel",
      required: true,
    },
    tableId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Table",
      required: true,
    },
  },
  { timestamps: true }
);

export default mongoose.model("Bill", billSchema);
