import mongoose from 'mongoose';

// Base schema for all customers
const customerBaseSchema = new mongoose.Schema({
  name: { type: String, required: true },
  hotelId: { type: mongoose.Schema.Types.ObjectId, ref: 'Hotel', required: true },
  tableId: { type: mongoose.Schema.Types.ObjectId, ref: 'Table', required: true },
}, {
  timestamps: true,
});

export default mongoose.model('Customer', customerBaseSchema);



