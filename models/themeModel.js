import mongoose from 'mongoose';

const themeSchema = new mongoose.Schema({
  hotelId: { type: mongoose.Schema.Types.ObjectId, ref: 'Hotel', required: true },  // Reference to the hotel
  logo: { type: String },  // URL to the logo image
  banner: { type: String },  // URL to the banner image
  primaryColor: { type: String, default: '#000000' },  // Primary theme color (hex code)
  secondaryColor: { type: String, default: '#FFFFFF' },  // Secondary theme color (hex code)
  backgroundColor: { type: String, default: '#F5F5F5' },  // Background color for UI
  fontFamily: { type: String, default: 'Arial, sans-serif' },  // Font family
  fontSize: { type: Number, default: 16 },  // Default font size (in pixels)
  buttonStyle: {  // Optional button styling
    borderRadius: { type: Number, default: 5 },  // Border radius for buttons (rounded edges)
    padding: { type: String, default: '10px 20px' }  // Padding for buttons (top-bottom, left-right)
  },
  navbarStyle: {  // Navbar specific styles
    backgroundColor: { type: String, default: '#000000' },  // Navbar background color
    textColor: { type: String, default: '#FFFFFF' }  // Navbar text color
  },
  footerStyle: {  // Footer specific styles
    backgroundColor: { type: String, default: '#333333' },  // Footer background color
    textColor: { type: String, default: '#FFFFFF' }  // Footer text color
  }
}, { timestamps: true });

export default mongoose.model('Theme', themeSchema);
