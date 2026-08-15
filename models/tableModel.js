import mongoose from "mongoose";
import { TABLE_STATUS } from "../utils/constant.js";

const tableSchema = new mongoose.Schema(
  {
    sequence: { type: Number, required: true, min: 1 },
    position: { type: String, trim: true },
    capacity: { type: Number, required: true, min: 1 },

    status: {
      type: String,
      enum: Object.values(TABLE_STATUS),
      default: TABLE_STATUS.FREE,
      index: true,
    },

    hotelId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Hotel",
      required: true,
      index: true,
    },

    QRId: { type: mongoose.Schema.Types.ObjectId, ref: "QR" },

    customer: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Customer",
      default: null,
    },

    /** Diners currently seated, for covers reporting. */
    covers: { type: Number, default: null, min: 0 },
    /** When the current party was seated — drives table-turn time. */
    occupiedAt: { type: Date, default: null },

    reservation: {
      name: { type: String, trim: true },
      phone: { type: String, trim: true },
      at: { type: Date },
      partySize: { type: Number, min: 1 },
    },

    isDeleted: { type: Boolean, default: false },
  },
  { timestamps: true }
);

/* Table numbers are unique within a restaurant, not across the platform. */
tableSchema.index({ sequence: 1, hotelId: 1 }, { unique: true });
tableSchema.index({ hotelId: 1, status: 1 });

/** Minutes the current party has been seated, for the floor view. */
tableSchema.virtual("seatedMinutes").get(function seatedMinutes() {
  if (!this.occupiedAt) return null;
  return Math.floor((Date.now() - this.occupiedAt.getTime()) / 60000);
});

tableSchema.set("toJSON", { virtuals: true });

export default mongoose.model("Table", tableSchema);
