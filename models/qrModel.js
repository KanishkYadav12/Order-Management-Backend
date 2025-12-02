import mongoose from 'mongoose';

const qrSchema = new mongoose.Schema({
  imageUrl: { type: String, required: true }, 
  code: { type: String, required: true, unique: true },
  tableId: { type: mongoose.Schema.Types.ObjectId, ref: 'Table', required: true },
  hotelId: { type: mongoose.Schema.Types.ObjectId, ref: 'Hotel', required: true }
}, { timestamps: true });

export default mongoose.model('QR', qrSchema);
