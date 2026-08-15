import express from "express";
import uploadStream from "../utils/memoryStorage.js";
import imageUploadService from "../services/imageUploadService.js";
import { protect } from "../middlewares/authMiddleware.js";
import { uploadLimiter } from "../middlewares/security.js";

const utilsRouter = express.Router();

/**
 * Image upload.
 *
 * Previously public, unlimited and untyped — free Cloudinary storage and
 * bandwidth on the operator's account for anyone who found the URL, plus a
 * path-injection surface via the client-supplied `folderName`.
 *
 * Now: authenticated, rate limited, size and MIME capped by `uploadStream`,
 * and the storage path is derived from the caller's own hotel rather than
 * from the request body.
 */
utilsRouter.post(
  "/",
  protect,
  uploadLimiter,
  uploadStream.single("logo"),
  imageUploadService
);

export default utilsRouter;
