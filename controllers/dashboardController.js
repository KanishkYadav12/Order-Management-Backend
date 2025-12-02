import { catchAsyncError } from "../middlewares/catchAsyncError.js";
import Bill from "../models/billModel.js";

const getOrderedItemsOfThisMonth = (currentMonthBills) => {
  const dishQuantities = currentMonthBills.reduce((acc, bill) => {
    bill.orderedItems.forEach((item) => {
      const dish = item.dishId;
      if (!acc[dish._id]) {
        acc[dish._id] = {
          dishName: dish.name,
          totalQuantity: 0,
          totalRevenue: 0,
        };
      }
      acc[dish._id].totalQuantity += item.quantity;
      acc[dish._id].totalRevenue += item.quantity * dish.price;
    });
    return acc;
  }, {});

  // Convert the accumulated data into an array of objects for sorting
  const dishQuantityArray = Object.entries(dishQuantities).map(
    ([dishId, data]) => ({
      id: dishId,
      name: data.dishName, // The full dish object
      totalQuantity: data.totalQuantity,
      totalRevenue: data.totalRevenue,
    })
  );

  // Sort the dishes by total quantity in descending order
  dishQuantityArray.sort((a, b) => b.totalQuantity - a.totalQuantity);

  return dishQuantityArray; // Return the array
};

export const getDashboardStats = catchAsyncError(async (req, res, next) => {
  const startOfMonth = new Date(
    new Date().getFullYear(),
    new Date().getMonth(),
    1
  );
  const endOfMonth = new Date(
    new Date().getFullYear(),
    new Date().getMonth() + 1,
    1
  );
  const hotelId = req.user.hotelId;
  const currentMonthBills = await Bill.find({
    hotelId,
    status: "paid",
    createdAt: {
      $gte: startOfMonth,
      $lt: endOfMonth,
    },
  }).populate("orderedItems.dishId");

  const groupedBillsByDate = currentMonthBills.reduce((acc, bill) => {
    const dateKey = new Date(bill.createdAt).toISOString().split("T")[0]; // Format as YYYY-MM-DD
    if (!acc[dateKey]) {
      acc[dateKey] = [];
    }
    acc[dateKey].push(bill);
    return acc;
  }, {});

  // Calculate the total number of bills by date
  const totalBillsByDate = Object.keys(groupedBillsByDate).reduce(
    (acc, date) => {
      const bills = groupedBillsByDate[date];
      acc[date] = bills.length; // The total number of bills for this date
      return acc;
    },
    {}
  );

  // Calculate the total revenue by date
  const revenueByDate = Object.keys(groupedBillsByDate).reduce((acc, date) => {
    const bills = groupedBillsByDate[date];
    const totalRevenue = bills.reduce((sum, bill) => sum + bill.finalAmount, 0);
    acc[date] = totalRevenue;
    return acc;
  }, {});

  // Calculate total monthly revenue
  const totalMonthlyRevenue = Object.values(revenueByDate).reduce(
    (sum, revenue) => sum + revenue,
    0
  );

  // Total bills for this month
  const totalBillsThisMonth = currentMonthBills.length;

  // Get today's date and calculate today's total bills and revenue
  const todayKey = new Date().toISOString().split("T")[0];
  const totalBillsToday = groupedBillsByDate[todayKey]?.length || 0;
  const todayRevenue = revenueByDate[todayKey] || 0;

  // Get the list of dishes ordered this month with quantity and revenue details
  const thisMonthDishes = getOrderedItemsOfThisMonth(currentMonthBills);

  // Respond with all the calculated statistics
  res.status(200).json({
    status: "success",
    message: "Dashboard stats fetched successfully",
    data: {
      revenue: { today: todayRevenue, monthly: totalMonthlyRevenue },
      customers: { today: totalBillsToday, monthly: totalBillsThisMonth },
      customersByDate: totalBillsByDate,
      revenueByDate,
      thisMonthDishes,
    },
  });
});
