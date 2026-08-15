import QRCode from "qrcode";
import env from "../config/env.js";
import { ServerError } from "../utils/errorHandler.js";

/**
 * Builds the URL a table's QR code points at.
 *
 * The base was hardcoded to a specific Vercel deployment; it now comes from
 * CUSTOMER_APP_URL so a printed QR always matches the deployment in use.
 */
export const buildTableUrl = (hotelId, tableId) =>
  `${env.CUSTOMER_APP_URL.replace(/\/$/, "")}/user/${hotelId}/${tableId}`;

export const createQrService = async (tableId, hotelId) => {
  try {
    const target = buildTableUrl(hotelId, tableId);

    const imageUrl = await QRCode.toDataURL(target, {
      width: 512,
      margin: 2,
      // High correction so the code still scans with a logo overlaid or with
      // a bit of wear on a printed table card.
      errorCorrectionLevel: "H",
      color: { dark: "#000000", light: "#ffffff" },
    });

    return { imageUrl, target };
  } catch (error) {
    throw new ServerError(`Could not generate the QR code: ${error.message}`);
  }
};

export const getQrService = (tableId, hotelId) =>
  createQrService(tableId, hotelId);
