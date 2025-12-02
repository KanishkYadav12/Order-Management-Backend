import mongoose from 'mongoose';

const hotelSchema = new mongoose.Schema({
  name: { type: String },
  location: { type: String },
  phone : {type: String},
  email : {type: String},
  ownerId: { type: mongoose.Schema.Types.ObjectId, ref: 'HotelOwner', required: true },
  logo: { type: String },
  description: { type: String },
  theme: { type: mongoose.Schema.Types.ObjectId, ref: 'Theme' } 
}, { timestamps: true });

export default mongoose.model('Hotel', hotelSchema);
