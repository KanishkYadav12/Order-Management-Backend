import mongoose from "mongoose";
import { BILL_STATUS, PAYMENT_METHODS } from "../utils/constant.js";

/**
 * A settled bill is a financial record, so line items store a snapshot of the
 * price and name at the time of sale rather than relying on a populate.
 * Re-pricing a dish next week must not silently rewrite last week's invoices.
 */
const lineItemSchema = new mongoose.Schema(
  {
    dishId: { type: mongoose.Schema.Types.ObjectId, ref: "Dish" },
    name: { type: String },
    quantity: { type: Number, required: true, min: 1 },
    unitPrice: { type: Number, min: 0 },
    /** Per-item discount from a dish-level offer. */
    discount: { type: Number, default: 0, min: 0 },
    taxRatePercent: { type: Number, default: 0, min: 0, max: 100 },
    lineTotal: { type: Number, default: 0, min: 0 },
  },
  { _id: false }
);

const paymentSchema = new mongoose.Schema(
  {
    method: {
      type: String,
      enum: Object.values(PAYMENT_METHODS),
      required: true,
    },
    amount: { type: Number, required: true, min: 0 },
    reference: { type: String, trim: true },
    receivedAt: { type: Date, default: Date.now },
    receivedBy: { type: mongoose.Schema.Types.ObjectId },
  },
  { _id: false }
);

const billSchema = new mongoose.Schema(
  {
    /** Human-facing invoice number, unique per restaurant per financial year. */
    invoiceNumber: { type: String, index: true },

    customerId: { type: mongoose.Schema.Types.ObjectId, ref: "Customer" },
    customerName: { type: String, required: true, trim: true },
    customerEmail: { type: String, trim: true, lowercase: true },
    customerPhone: { type: String, trim: true },

    orderedItems: [lineItemSchema],

    globalOffer: { type: mongoose.Schema.Types.ObjectId, ref: "Offer" },

    /* ── Money ──────────────────────────────────────────────────────────
       Every figure is derived and recomputed by recalculateBill(); none of
       them are incremented in place. The previous updateBill did
       `totalDiscount += discount` on each edit, so editing a bill twice
       applied the discount twice. */
    subTotal: { type: Number, default: 0, min: 0 },
    /** Discount from dish-level offers. */
    itemDiscount: { type: Number, default: 0, min: 0 },
    /** Discount from a global offer applied to the whole bill. */
    offerDiscount: { type: Number, default: 0, min: 0 },
    /** Manual discount entered by staff. */
    customDiscount: { type: Number, default: 0, min: 0 },
    totalDiscount: { type: Number, default: 0, min: 0 },

    taxableAmount: { type: Number, default: 0, min: 0 },
    /** Split for GST invoicing; equal halves of the total tax. */
    cgst: { type: Number, default: 0, min: 0 },
    sgst: { type: Number, default: 0, min: 0 },
    totalTax: { type: Number, default: 0, min: 0 },

    serviceChargePercent: { type: Number, default: 0, min: 0, max: 100 },
    serviceCharge: { type: Number, default: 0, min: 0 },

    /** Rounding applied so the payable figure lands on a whole rupee. */
    roundOff: { type: Number, default: 0 },

    /** Legacy alias for subTotal; kept so existing screens keep rendering. */
    totalAmount: { type: Number, default: 0, min: 0 },
    finalAmount: { type: Number, default: 0, min: 0 },

    amountPaid: { type: Number, default: 0, min: 0 },
    payments: [paymentSchema],

    status: {
      type: String,
      enum: Object.values(BILL_STATUS),
      default: BILL_STATUS.UNPAID,
      index: true,
    },

    hotelId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Hotel",
      required: true,
      index: true,
    },
    tableId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Table",
      required: true,
      index: true,
    },

    /* ── Audit ─────────────────────────────────────────────────────────── */
    settledBy: { type: mongoose.Schema.Types.ObjectId },
    settledAt: { type: Date },
    voidedBy: { type: mongoose.Schema.Types.ObjectId },
    voidReason: { type: String, trim: true },
    notes: { type: String, trim: true, maxlength: 500 },
  },
  { timestamps: true }
);

/* Reporting reads bills by hotel, by status and by date. */
billSchema.index({ hotelId: 1, status: 1, createdAt: -1 });
billSchema.index({ hotelId: 1, createdAt: -1 });

/**
 * Invoice numbers are unique per restaurant — but only once assigned.
 *
 * This was `{ unique: true, sparse: true }`, which does not do what it looks
 * like on a *compound* index: sparse only skips a document when **every**
 * indexed field is absent. `hotelId` is always present, so every bill was
 * indexed, and two unpaid bills for the same restaurant both keyed as
 * `{hotelId, null}` — the second one failed with a duplicate-key error.
 * Opening a bill on a second table was therefore impossible.
 *
 * A partial index indexes only documents that actually carry an invoice
 * number, which is precisely the set the uniqueness rule is about.
 */
billSchema.index(
  { hotelId: 1, invoiceNumber: 1 },
  {
    unique: true,
    partialFilterExpression: { invoiceNumber: { $type: "string" } },
  }
);

/** Outstanding balance on a partially paid bill. */
billSchema.virtual("balanceDue").get(function balanceDue() {
  return Math.max(0, (this.finalAmount ?? 0) - (this.amountPaid ?? 0));
});

billSchema.set("toJSON", { virtuals: true });

export default mongoose.model("Bill", billSchema);
