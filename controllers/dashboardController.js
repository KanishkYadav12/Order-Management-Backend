import { catchAsyncError } from "../middlewares/catchAsyncError.js";
import { getDashboardStatsService } from "../services/dashboardServices.js";

export const getDashboardStats = catchAsyncError(async (req, res) => {
  const stats = await getDashboardStatsService(req.hotelId, {
    from: req.query.from,
    to: req.query.to,
  });

  res.status(200).json({
    status: "success",
    message: "Dashboard loaded",
    data: stats,
  });
});
