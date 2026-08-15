import mongoose from "mongoose";

const hotelSchema = new mongoose.Schema(
  {
    name: { type: String, trim: true, maxlength: 120 },
    location: { type: String, trim: true, maxlength: 300 },
    phone: { type: String, trim: true },
    email: { type: String, trim: true, lowercase: true },

    ownerId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "HotelOwner",
      required: true,
      index: true,
    },

    logo: { type: String },
    banner: { type: String },
    description: { type: String, trim: true, maxlength: 1000 },
    theme: { type: mongoose.Schema.Types.ObjectId, ref: "Theme" },

    /* ── Billing configuration ───────────────────────────────────────────
       Bills could not previously carry tax at all, which makes them
       unusable as invoices for an Indian restaurant. */
    billing: {
      /** Goods & Services Tax identification number, printed on the invoice. */
      gstin: { type: String, trim: true, uppercase: true, maxlength: 15 },
      /** Default GST rate; a dish may override it with its own rate. */
      taxRatePercent: { type: Number, default: 5, min: 0, max: 100 },
      /** Whether menu prices already include tax. */
      pricesIncludeTax: { type: Boolean, default: false },
      serviceChargePercent: { type: Number, default: 0, min: 0, max: 100 },
      currency: { type: String, default: "INR", maxlength: 3 },
      currencySymbol: { type: String, default: "₹", maxlength: 3 },
      /** Round the payable figure to the nearest whole unit. */
      roundOffEnabled: { type: Boolean, default: true },
      invoicePrefix: { type: String, default: "INV", trim: true, maxlength: 8 },
      /** Monotonic counter behind invoiceNumber. */
      invoiceCounter: { type: Number, default: 0, min: 0 },
      footerNote: {
        type: String,
        trim: true,
        maxlength: 300,
        default: "Thank you for dining with us!",
      },
    },

    /** Shown on the customer menu and used to gate ordering. */
    serviceHours: {
      opensAt: { type: String, default: "09:00" },
      closesAt: { type: String, default: "23:00" },
      acceptingOrders: { type: Boolean, default: true },
    },

    isActive: { type: Boolean, default: true },
  },
  { timestamps: true }
);

export default mongoose.model("Hotel", hotelSchema);
