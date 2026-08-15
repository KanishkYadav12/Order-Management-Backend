import nodemailer from "nodemailer";
import env from "./env.js";
import logger from "../utils/logger.js";

/**
 * SMTP transport.
 *
 * `port` was previously spelled `PORT`, which nodemailer ignores — the
 * connection fell back to the `service: "gmail"` defaults and the configured
 * port was never used. Both are set correctly here, and `secure` is derived
 * from the port rather than hardcoded to false.
 */
const transporter = nodemailer.createTransport({
  host: env.EMAIL_HOST,
  port: env.EMAIL_PORT,
  secure: env.EMAIL_PORT === 465, // 465 is implicit TLS; 587 upgrades via STARTTLS
  auth: {
    user: env.EMAIL_USER,
    pass: env.EMAIL_PASS,
  },
  pool: true,
  maxConnections: 3,
  maxMessages: 50,
});

// Verify once at boot so a bad SMTP config surfaces in the logs immediately
// rather than on the first user who tries to register.
transporter
  .verify()
  .then(() => logger.info("SMTP transport ready"))
  .catch((err) => logger.error({ err }, "SMTP transport unavailable"));

export default transporter;
