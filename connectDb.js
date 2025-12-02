import mongoose from "mongoose";

const connectDb = async (DATABASE_URL) => {
  const dbOptions = {
    dbName: "HotelOrderManagementSystem", 
  };

  try {
    // Connect to MongoDB
    await mongoose.connect(DATABASE_URL, dbOptions);
    console.log("Database connected successfully...");
  } catch (err) {
    
    console.error("Database connection error:", err);
    process.exit(1);
  }
};

export default connectDb;
