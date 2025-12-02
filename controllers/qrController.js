import { createQrService, getQrService } from "../services/qrService.js";
import { generatePdfService } from "../services/pdfGenerationService.js";
import { catchAsyncError } from "../middlewares/catchAsyncError.js";
import Table from "../models/tableModel.js";
import Hotel from "../models/hotelModel.js";

// Generate QR code
// export const generateQr = catchAsyncError(async (req, res, next) => {
//     const { tableId } = req.params; // Table ID from the URL parameters

//     // Assuming the hotelId can be derived or passed separately (e.g., req.user.hotelId if authenticated)
//     const hotelId = req.user.hotelId; // Replace with actual source of hotelId

//     const qrCode = await createQrService(tableId, hotelId);
//     res.status(201).json({ message: "QR Code Generated", qrCode });
// });

// Print QR code as a downloadable PDF
export const printQr = catchAsyncError(async (req, res, next) => {
    const { tableId } = req.params; // Table ID from the URL parameters\

    const table = await Table.findById(tableId);

    const tableNumber = table.sequence;
    const hotelId = req.user.hotelId;

    const hotel = await Hotel.findById(hotelId);

    const hotelName = hotel.name;

    // const qrCodeData = await getQrService(tableId, hotelId);
    // const pdfBuffer = await generatePdfService(qrCodeData.imageUrl, tableId, tableNumber, hotelName);

    //2nd code ----
    // const qrCodeImage = await createQrService(tableId, hotelId);
    // const pdfBuffer = await generatePdfService(qrCodeImage.imageUrl, tableId, tableNumber, hotelName);

    // res.setHeader('Content-Type', 'application/pdf');
    // res.setHeader('Content-Disposition', `attachment; filename=table-${tableId}-qr.pdf`);
    // res.end(pdfBuffer);

    //3rd code ----
    const qrCodeImage = await createQrService(tableId, hotelId);
    res.status(200).json({message:"QR Code Generated", qrCodeImage , tableNumber , hotelName , tableId,hotelId });
});
