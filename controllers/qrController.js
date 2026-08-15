import { createQrService } from "../services/qrService.js";
import { catchAsyncError } from "../middlewares/catchAsyncError.js";
import Table from "../models/tableModel.js";
import Hotel from "../models/hotelModel.js";
import { NotFoundError } from "../utils/errorHandler.js";

/**
 * Returns the QR code for a table, as a data URL the dashboard can render
 * and print.
 *
 * The table is looked up scoped to the caller's restaurant, so a QR for
 * another hotel's table can't be generated.
 */
export const printQr = catchAsyncError(async (req, res) => {
  const { tableId } = req.params;

  const table = await Table.findOne({
    _id: tableId,
    hotelId: req.hotelId,
    isDeleted: false,
  });
  if (!table) throw new NotFoundError("Table");

  const hotel = await Hotel.findById(req.hotelId).select("name logo location");
  const { imageUrl, target } = await createQrService(tableId, req.hotelId);

  res.status(200).json({
    status: "success",
    message: "QR code generated",
    data: {
      qrCodeImage: { imageUrl },
      // Flat keys retained: the existing QR modal reads them directly.
      imageUrl,
      target,
      tableNumber: table.sequence,
      tableId,
      hotelId: req.hotelId,
      hotelName: hotel?.name ?? "",
      hotelLogo: hotel?.logo ?? "",
    },
  });
});

export default printQr;
