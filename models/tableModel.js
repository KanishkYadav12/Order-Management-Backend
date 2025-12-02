import mongoose from 'mongoose';

const tableSchema = new mongoose.Schema({
  sequence: { type: Number, required: true}, 
  position: { type: String }, 
  capacity: { type: Number, required: true },
  status: { type: String, enum: ['occupied', 'free'], default: 'free' }, 
  hotelId: { type: mongoose.Schema.Types.ObjectId, ref: 'Hotel', required: true },
  QRId: { type: mongoose.Schema.Types.ObjectId, ref: 'QR' },
  customer : {type: mongoose.Schema.Types.ObjectId , ref : 'Customer', default : null } 
}, { timestamps: true });

tableSchema.index({ sequence: 1, hotelId: 1 }, { unique: true });
export default mongoose.model('Table', tableSchema);
