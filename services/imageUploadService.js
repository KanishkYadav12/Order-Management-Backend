import { catchAsyncError } from "../middlewares/catchAsyncError.js";
import uploadAndGetAvatarUrl from "../utils/uploadAndGetUrl.js";
import { ClientError } from "../utils/errorHandler.js";

/** Folder names the client is permitted to write into. */
const ALLOWED_FOLDERS = new Set([
  "dish",
  "category",
  "ingredient",
  "offer",
  "hotel",
  "profile",
  "banner",
]);

/** Strips anything that could traverse or escape the intended Cloudinary path. */
const sanitiseSegment = (value, fallback) => {
  const cleaned = String(value ?? "")
    .trim()
    .replace(/[^a-zA-Z0-9_-]/g, "");
  return cleaned.slice(0, 64) || fallback;
};

const imageUploadService = catchAsyncError(async (req, res) => {
  if (!req.file) {
    throw new ClientError("No image was provided.", 400, "NO_FILE");
  }

  const folder = String(req.body?.folderName ?? "").trim().toLowerCase();
  if (!ALLOWED_FOLDERS.has(folder)) {
    throw new ClientError(
      `Unknown upload folder. Expected one of: ${[...ALLOWED_FOLDERS].join(", ")}.`,
      400,
      "INVALID_UPLOAD_FOLDER"
    );
  }

  // Scope every upload under the caller's own hotel so one tenant can neither
  // overwrite nor enumerate another's media.
  const hotelSegment = req.user?.hotelId
    ? req.user.hotelId.toString()
    : `user-${req.user._id.toString()}`;

  const fileName = sanitiseSegment(req.body?.fileName, Date.now().toString());

  const url = await uploadAndGetAvatarUrl(
    req.file,
    `OMS/${hotelSegment}/${folder}`,
    fileName,
    "stream"
  );

  return res.status(201).json({
    status: "success",
    message: "Image uploaded",
    data: { url },
  });
});

export default imageUploadService;
