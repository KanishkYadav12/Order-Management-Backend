import transporter from "../config/emailConfig.js";
import env from "../config/env.js";
import logger from "./logger.js";

/** Escapes user-supplied values before they go into an HTML email body. */
const escapeHtml = (value) =>
  String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

/**
 * Shared shell for every transactional email.
 *
 * Table-based and inline-styled on purpose: that is what survives Outlook and
 * Gmail. Colours are literal because email clients do not support CSS
 * variables or, reliably, prefers-color-scheme.
 */
const layout = ({ title, body, footer }) => `
<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)}</title></head>
<body style="margin:0;padding:0;background:#f4f5f7;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f5f7;padding:32px 12px;">
    <tr><td align="center">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
             style="max-width:520px;background:#ffffff;border-radius:10px;overflow:hidden;
                    font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;
                    box-shadow:0 1px 3px rgba(16,24,40,.08);">
        <tr><td style="padding:26px 32px 18px;border-bottom:1px solid #eaecf0;">
          <div style="font-size:17px;font-weight:700;color:#101828;letter-spacing:-.01em;">QR&#8209;Dine</div>
        </td></tr>
        <tr><td style="padding:30px 32px;color:#344054;font-size:15px;line-height:1.6;">
          ${body}
        </td></tr>
        <tr><td style="padding:18px 32px 26px;border-top:1px solid #eaecf0;color:#98a2b3;font-size:12px;line-height:1.5;">
          ${footer ?? "You are receiving this because you have a QR-Dine account."}
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`;

/**
 * Low-level send. Never throws into the request path — callers decide whether
 * a mail failure should surface, and most should not.
 *
 * @returns {Promise<boolean>} whether the message was accepted by the server
 */
export const sendEmail = async (to, subject, html, { text } = {}) => {
  try {
    const info = await transporter.sendMail({
      from: env.EMAIL_FROM,
      to,
      subject,
      html,
      text: text ?? html.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim(),
    });
    logger.info({ to, subject, messageId: info.messageId }, "email sent");
    return true;
  } catch (err) {
    logger.error({ err, to, subject }, "email failed to send");
    return false;
  }
};

/* ── Templates ────────────────────────────────────────────────────────── */

export const sendOtpEmail = (to, code, name) =>
  sendEmail(
    to,
    "Your QR-Dine verification code",
    layout({
      title: "Verify your email",
      body: `
        <p style="margin:0 0 14px;">Hi ${escapeHtml(name ?? "there")},</p>
        <p style="margin:0 0 20px;">Use this code to confirm your email address:</p>
        <div style="font-size:32px;font-weight:700;letter-spacing:.24em;color:#101828;
                    background:#f9fafb;border:1px solid #eaecf0;border-radius:8px;
                    padding:18px;text-align:center;font-family:ui-monospace,Menlo,Consolas,monospace;">
          ${escapeHtml(code)}
        </div>
        <p style="margin:20px 0 0;color:#667085;font-size:14px;">
          This code expires in 10 minutes. If you didn't sign up, you can ignore this email.
        </p>`,
      footer: "Never share this code. QR-Dine staff will never ask you for it.",
    })
  );

export const sendPasswordResetEmail = (to, resetUrl, name) =>
  sendEmail(
    to,
    "Reset your QR-Dine password",
    layout({
      title: "Reset your password",
      body: `
        <p style="margin:0 0 14px;">Hi ${escapeHtml(name ?? "there")},</p>
        <p style="margin:0 0 22px;">Click the button below to choose a new password.</p>
        <a href="${escapeHtml(resetUrl)}"
           style="display:inline-block;background:#101828;color:#ffffff;text-decoration:none;
                  padding:12px 22px;border-radius:8px;font-weight:600;font-size:15px;">
          Reset password
        </a>
        <p style="margin:22px 0 0;color:#667085;font-size:14px;">
          This link expires in 10 minutes. If you didn't request it, nothing has changed
          and you can safely ignore this email.
        </p>
        <p style="margin:14px 0 0;color:#98a2b3;font-size:12px;word-break:break-all;">
          ${escapeHtml(resetUrl)}
        </p>`,
    })
  );

export const sendMembershipExpiredEmail = (to, { name, expiredOn }) =>
  sendEmail(
    to,
    "Your QR-Dine subscription has expired",
    layout({
      title: "Subscription expired",
      body: `
        <p style="margin:0 0 14px;">Hi ${escapeHtml(name ?? "there")},</p>
        <p style="margin:0 0 16px;">
          Your subscription ended on <strong>${escapeHtml(expiredOn)}</strong>, so your
          dashboard is paused. Your menu, tables and history are all safe.
        </p>
        <p style="margin:0;color:#667085;font-size:14px;">
          Renew to pick up exactly where you left off.
        </p>`,
    })
  );

/** Legacy default export: sendEmail(to, subject, htmlBody). */
export default sendEmail;
