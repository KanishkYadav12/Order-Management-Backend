import mongoose from "mongoose";

export const catchAsyncError =
  (theFun, withTransaction = false) =>
  async (req, res, next) => {
    let session = null;
    
    if (withTransaction) {
      session = await mongoose.startSession();
      session.startTransaction();
    }

    try {
      await theFun(req, res, next, session);
      if (session) await session.commitTransaction();
    } catch (err) {
      console.log(" Entered in catch block of theFun----");
      if (session) await session.abortTransaction();
      next(err);
    } finally {
      console.log("Entered in finally----");
      if (session) session.endSession();
      console.log("After ending session----");
    }
    // theFun(req, res, next).catch(next);
  };
