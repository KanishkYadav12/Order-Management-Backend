import multer from "multer";
import { ClientError } from "./errorHandler.js";

/** Image types the product actually uses: logos, banners, dish photos. */
const ALLOWED_MIME_TYPES = new Set([
  "image/jpeg",
  "image/png",
  "image/webp",
  "image/gif",
  "image/avif",
]);

const MAX_FILE_BYTES = 5 * 1024 * 1024; // 5 MB

/**
 * In-memory upload handler, bounded on every axis multer exposes.
 *
 * The previous configuration was `multer({ storage })` with no limits at all:
 * unbounded file size, unbounded field count, and any content type accepted —
 * on a route that required no authentication.
 *
 * Note the mimetype check is a first filter, not proof of file type; it is
 * client-supplied. Cloudinary re-encodes what it receives, which is what
 * actually neutralises a disguised payload.
 */
const uploadStream = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: MAX_FILE_BYTES,
    files: 1,
    fields: 10,
    fieldNameSize: 100,
    fieldSize: 1024 * 100,
  },
  fileFilter: (req, file, callback) => {
    if (!ALLOWED_MIME_TYPES.has(file.mimetype)) {
      return callback(
        new ClientError(
          `Unsupported file type. Allowed formats: JPEG, PNG, WebP, GIF, AVIF.`,
          400,
          "UNSUPPORTED_FILE_TYPE"
        )
      );
    }
    callback(null, true);
  },
});

export { ALLOWED_MIME_TYPES, MAX_FILE_BYTES };
export default uploadStream;
