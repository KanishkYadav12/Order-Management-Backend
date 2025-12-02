import mongoose from "mongoose";

const orderSchema = new mongoose.Schema(
  {
    customerId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Customer",
      required: true,
    },
    dishes: [
      {
        dishId: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "Dish",
          required: true,
        },
        quantity: {
          type: Number,
          required: true,
        },
        note: { type: String },
      },
    ],
    status: {
      type: String,
      enum: ["draft", "pending", "preparing", "completed", "cancelled"],
      default: "draft",
    },
    tableId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Table",
      required: true,
    },
    hotelId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Hotel",
      required: true,
    },
    note: {
      type: String,
      default: "",
    },
    isFirstOrder: {
      type: Boolean,
      default: false,
    }, //to update table while receiving published order
  },
  { timestamps: true }
);

export default mongoose.model("Order", orderSchema);
