import express from "express";
import {
  generateDevKey,
  getAllDevKeys,
  useDevKey,
} from "../controllers/devKeyController.js";
import { protect, superAdminOnly } from "../middlewares/authMiddleware.js";

const router = express.Router();

/**
 * Dev keys are single-use invitations to create a super-admin account.
 *
 * These routes were previously unauthenticated, which meant anyone could mint
 * a key and then register themselves as a super admin — full control of every
 * tenant on the platform, from two anonymous requests.
 *
 * Every route now requires an existing super admin. The very first super admin
 * is created out-of-band with `npm run seed:superadmin`, which is the only way
 * to bootstrap the chain.
 */
router.use(protect, superAdminOnly);

router.post("/generate", generateDevKey);
router.get("/", getAllDevKeys);
router.put("/use", useDevKey);

export default router;
