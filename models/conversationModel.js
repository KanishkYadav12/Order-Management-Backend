import mongoose from "mongoose";

/**
 * One owner's ongoing conversation with their advisor.
 *
 * Memory is what separates an assistant from a search box: "and what about
 * next weekend?" only means something if the previous turn is still there.
 *
 * Turns are capped rather than unbounded — every turn is replayed into the
 * model's context, so an unlimited history would slowly turn one question into
 * an expensive one and eventually exceed the window.
 */
const turnSchema = new mongoose.Schema(
  {
    role: { type: String, enum: ["user", "model"], required: true },
    text: { type: String, required: true, maxlength: 8000 },
    /** Which reports were run to produce this answer, for transparency. */
    toolsUsed: [{ type: String }],
    at: { type: Date, default: Date.now },
  },
  { _id: false }
);

const conversationSchema = new mongoose.Schema(
  {
    hotelId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Hotel",
      required: true,
      index: true,
    },
    userId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
    title: { type: String, trim: true, maxlength: 120 },
    turns: [turnSchema],
  },
  { timestamps: true }
);

conversationSchema.index({ hotelId: 1, userId: 1, updatedAt: -1 });

/** Keeps the replayed history bounded. */
const MAX_TURNS = 40;

conversationSchema.pre("save", function trimTurns(next) {
  if (this.turns.length > MAX_TURNS) {
    this.turns = this.turns.slice(-MAX_TURNS);
  }
  next();
});

export default mongoose.model("Conversation", conversationSchema);
