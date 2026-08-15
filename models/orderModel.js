import mongoose from "mongoose";
import { ORDER_STATUS } from "../utils/constant.js";

const orderItemSchema = new mongoose.Schema(
  {
    dishId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Dish",
      required: true,
    },
    quantity: { type: Number, required: true, min: 1 },
    /**
     * Price at the moment the order was placed. Without this, repricing the
     * menu mid-service silently changes what an already-placed order costs.
     */
    unitPrice: { type: Number, min: 0 },
    note: { type: String, trim: true, maxlength: 200 },
  },
  { _id: false }
);

const orderSchema = new mongoose.Schema(
  {
    customerId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Customer",
      required: true,
      index: true,
    },

    dishes: [orderItemSchema],

    status: {
      type: String,
      enum: Object.values(ORDER_STATUS),
      default: ORDER_STATUS.DRAFT,
      index: true,
    },

    tableId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Table",
      required: true,
      index: true,
    },
    hotelId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Hotel",
      required: true,
      index: true,
    },

    note: { type: String, default: "", trim: true, maxlength: 500 },

    /** Marks the order that first seated the table. */
    isFirstOrder: { type: Boolean, default: false },

    /** Who took the order, when it was placed by staff rather than a diner. */
    placedBy: { type: mongoose.Schema.Types.ObjectId },

    /** Kitchen timing, for prep-time reporting. */
    confirmedAt: { type: Date },
    startedAt: { type: Date },
    readyAt: { type: Date },
    completedAt: { type: Date },

    cancelReason: { type: String, trim: true, maxlength: 300 },
  },
  { timestamps: true }
);

/* The kitchen board query: live orders for one hotel, oldest first. */
orderSchema.index({ hotelId: 1, status: 1, createdAt: 1 });
orderSchema.index({ tableId: 1, status: 1 });

/** Stamps the timing field matching whichever status was just set. */
orderSchema.pre("save", function stampTiming(next) {
  if (!this.isModified("status")) return next();

  const now = new Date();
  const stamp = {
    [ORDER_STATUS.PENDING]: "confirmedAt",
    [ORDER_STATUS.PREPARING]: "startedAt",
    [ORDER_STATUS.READY]: "readyAt",
    [ORDER_STATUS.COMPLETED]: "completedAt",
  }[this.status];

  if (stamp && !this[stamp]) this[stamp] = now;
  next();
});

/** Minutes from confirmation to ready, for the prep-time report. */
orderSchema.virtual("prepMinutes").get(function prepMinutes() {
  if (!this.confirmedAt || !this.readyAt) return null;
  return Math.round((this.readyAt - this.confirmedAt) / 60000);
});

orderSchema.set("toJSON", { virtuals: true });

export default mongoose.model("Order", orderSchema);
