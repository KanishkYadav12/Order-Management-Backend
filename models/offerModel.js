import mongoose from "mongoose";

const offerSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    logo: { type: String },
    appliedOn: [{ type: mongoose.Schema.Types.ObjectId, ref: "Dish" }],
    type: { type: String, enum: ["specific", "global"], required: true },
    discountType: { type: String, enum: ["percent", "amount"], required: true },
    value: { type: Number, required: true, min: 0 },
    hotelId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Hotel",
      required: true,
    },
    appliedAbove: {
      type: Number,
      min: 0,
    },
    disable: { type: Boolean, default: false },
    startDate: { type: Date, default: Date.now },
    endDate: {
      type: Date,
      default: () => new Date(Date.now() + 30 * 6 * 24 * 60 * 60 * 1000),
    },
    description: { type: String, default: "" },
  },
  { timestamps: true }
);

export default mongoose.model("Offer", offerSchema);
