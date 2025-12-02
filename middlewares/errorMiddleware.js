export const  error = (err, req, res, next) => {
    // Log the error details for debugging
    console.error("Error details : ", err);
  
    // Default error message and status
    err.message = err.message || "Internal server error";
    err.statusCode = err.statusCode || 500;
  
    // Handling specific error cases
    if (err.code === 11000) {
      // MongoDB Duplicate key error
      err.message = `${Object.keys(err.keyValue)} already exists, please try another.`;
      err.statusCode = 400;              
    } else if (err.name === "CastError") {
      // Mongoose invalid ID error
      err.message = `${err.path} is invalid!`;
      err.statusCode = 400;
    } else if (err.name === "ValidationError") {
      // Mongoose validation error
      err.message = `Validation failed: ${Object.values(err.errors).map(val => val.message).join(", ")}`;
      err.statusCode = 400;
    } else if (err.name === "JsonWebTokenError" || err.name === "TokenExpiredError") {
      // JWT related errors
      err.message = "Invalid or expired token!";
      err.statusCode = 401;
    } else if (err.name === "TypeError") {
      // Handle any other unexpected errors gracefully
      err.message = "Internal server error";
      err.statusCode = 500;
    }
  
    // Custom error handling based on error type (optional)
    // if (err.type === "ClientError" && err.name === "AllRequired") {
    //   err.message = "All fields are required!";
    // }

    
    // Send the error response
    return res.status(err.statusCode).json({
      status: "failed",
      message: err.message,
      errorDetails : err,
      // You may optionally add the stack trace for development environments
      ...(process.env.NODE_ENV === 'development' && { stack: err.stack }),
    });
  };
  