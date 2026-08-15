import mongoose from "mongoose";

/* ── Category ─────────────────────────────────────────────────────────── */

const categorySchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 60 },
    logo: { type: String },
    description: { type: String, trim: true, maxlength: 300 },
    /** Controls the order sections appear in on the customer menu. */
    displayOrder: { type: Number, default: 0 },
    isDeleted: { type: Boolean, default: false },
    hotelId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Hotel",
      required: true,
      index: true,
    },
  },
  { timestamps: true }
);

// Category names are unique per restaurant, not globally.
categorySchema.index({ hotelId: 1, name: 1 }, { unique: true });
categorySchema.index({ hotelId: 1, displayOrder: 1 });

/* ── Ingredient ───────────────────────────────────────────────────────── */

const ingredientSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 60 },
    logo: { type: String },
    description: { type: String, trim: true, maxlength: 300 },
    hotelId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Hotel",
      required: true,
      index: true,
    },

    /**
     * Stock tracking. All optional — an ingredient without a unit simply is
     * not tracked, so existing records stay valid and restaurants can adopt
     * inventory per-ingredient rather than all at once.
     */
    unit: {
      type: String,
      enum: ["g", "kg", "ml", "l", "piece", "packet", null],
      default: null,
    },
    stockQuantity: { type: Number, default: null, min: 0 },
    lowStockThreshold: { type: Number, default: null, min: 0 },
    costPerUnit: { type: Number, default: null, min: 0 },
    isDeleted: { type: Boolean, default: false },
  },
  { timestamps: true }
);

ingredientSchema.index({ hotelId: 1, name: 1 }, { unique: true });

/** True when this ingredient is tracked and has fallen to its threshold. */
ingredientSchema.virtual("isLowStock").get(function isLowStock() {
  if (this.stockQuantity == null || this.lowStockThreshold == null) return false;
  return this.stockQuantity <= this.lowStockThreshold;
});

ingredientSchema.set("toJSON", { virtuals: true });

/* ── Dish ─────────────────────────────────────────────────────────────── */

const dishSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
      minlength: 3,
      maxlength: 100,
    },
    logo: {
      type: String,
      default:
        "https://static.vecteezy.com/system/resources/previews/010/354/788/original/main-dish-icon-colorful-flat-design-illustration-graphics-free-vector.jpg",
    },
    offer: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Offer",
      default: null,
    },
    quantity: { type: Number, default: 1, min: 1 },
    price: { type: Number, required: true, min: 0 },

    preparationTime: {
      type: String,
      validate: {
        validator: (v) => !v || /^\d+\s*(minutes?|mins?)$/i.test(v),
        message: 'Preparation time should look like "15 minutes".',
      },
    },

    description: { type: String, trim: true, maxlength: 500 },

    category: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Category",
      default: null,
      index: true,
    },

    /**
     * Quantities consumed per portion, used to decrement stock when an order
     * completes. `ingredients` is retained as the plain reference list the
     * existing UI reads.
     */
    ingredients: [{ type: mongoose.Schema.Types.ObjectId, ref: "Ingredient" }],
    recipe: [
      {
        ingredientId: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "Ingredient",
        },
        quantity: { type: Number, min: 0 },
      },
    ],

    hotelId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Hotel",
      required: true,
      index: true,
    },

    /** Overrides the hotel's default tax rate when set. */
    taxRatePercent: { type: Number, default: null, min: 0, max: 100 },

    isVegetarian: { type: Boolean, default: null },
    spiceLevel: {
      type: String,
      enum: ["none", "mild", "medium", "hot", null],
      default: null,
    },

    bestSeller: { type: Boolean, default: false },
    outOfStock: { type: Boolean, default: false },
    isDeleted: { type: Boolean, default: false },
    deletedAt: { type: Date, default: null },
  },
  { timestamps: true }
);

/* The menu query — by hotel, excluding deleted — runs on every page load. */
dishSchema.index({ hotelId: 1, isDeleted: 1 });
dishSchema.index({ hotelId: 1, category: 1, isDeleted: 1 });
dishSchema.index({ hotelId: 1, name: 1 });

export const Category = mongoose.model("Category", categorySchema);
export const Ingredient = mongoose.model("Ingredient", ingredientSchema);
export const Dish = mongoose.model("Dish", dishSchema);
