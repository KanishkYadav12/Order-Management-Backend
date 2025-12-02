import mongoose from 'mongoose';

// DevKey Schema
const devKeySchema = new mongoose.Schema(
  {
    key: { 
      type: String, 
      required: true, 
      unique: true,  
    },
    createdAt: { 
      type: Date, 
      default: Date.now,
    },
    isUsed: { 
      type: Boolean, 
      default: false,  
    },
    expirationDate: { 
      type: Date, 
      required: true,  
      validate: {
        validator: function(value) {
          return value > Date.now(); 
        },
        message: 'Expiration date must be in the future',
      },
    },
  },
  { timestamps: true } 
);

devKeySchema.virtual('isExpired').get(function() {
  return this.expirationDate < Date.now();
});

export default mongoose.model('DevKey', devKeySchema);
