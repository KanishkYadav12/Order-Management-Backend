/**
 * Invoice HTML.
 *
 * Rendered for both email and the printable view, so it is table-based and
 * inline-styled — that is what survives email clients and thermal-printer
 * browsers alike. Colours are literal for the same reason.
 */

const escapeHtml = (value) =>
  String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

const money = (amount, symbol = "₹") =>
  `${symbol}${Number(amount ?? 0).toFixed(2)}`;

const row = (label, value, { bold = false, muted = false, negative = false } = {}) => `
  <tr>
    <td style="padding:6px 0;color:${muted ? "#98a2b3" : "#475467"};font-size:${bold ? "15px" : "14px"};
               font-weight:${bold ? "700" : "400"};">${escapeHtml(label)}</td>
    <td style="padding:6px 0;text-align:right;font-size:${bold ? "16px" : "14px"};
               font-weight:${bold ? "700" : "500"};
               color:${negative ? "#067647" : "#101828"};
               font-variant-numeric:tabular-nums;">${negative ? "−" : ""}${value}</td>
  </tr>`;

/**
 * @param {object} bill    Populated bill document
 * @param {object} [hotel] Falls back to bill.hotelId when populated
 */
export const renderInvoiceHtml = (bill, hotel = bill.hotelId) => {
  const symbol = hotel?.billing?.currencySymbol ?? "₹";
  const gstin = hotel?.billing?.gstin;

  const itemRows = (bill.orderedItems ?? [])
    .map((item) => {
      const name = item.name ?? item.dishId?.name ?? "Item";
      const unitPrice = item.unitPrice ?? item.dishId?.price ?? 0;
      const lineTotal = item.lineTotal ?? unitPrice * item.quantity;

      return `
        <tr>
          <td style="padding:11px 0;border-bottom:1px solid #f2f4f7;font-size:14px;color:#101828;">
            ${escapeHtml(name)}
            ${item.discount > 0 ? `<span style="color:#067647;font-size:12px;"> · offer applied</span>` : ""}
          </td>
          <td style="padding:11px 8px;border-bottom:1px solid #f2f4f7;text-align:center;font-size:14px;
                     color:#475467;font-variant-numeric:tabular-nums;">${item.quantity}</td>
          <td style="padding:11px 0;border-bottom:1px solid #f2f4f7;text-align:right;font-size:14px;
                     color:#475467;font-variant-numeric:tabular-nums;">${money(unitPrice, symbol)}</td>
          <td style="padding:11px 0 11px 8px;border-bottom:1px solid #f2f4f7;text-align:right;font-size:14px;
                     color:#101828;font-weight:600;font-variant-numeric:tabular-nums;">${money(lineTotal, symbol)}</td>
        </tr>`;
    })
    .join("");

  const issuedAt = new Date(bill.settledAt ?? bill.createdAt ?? Date.now());

  return `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Invoice ${escapeHtml(bill.invoiceNumber ?? bill._id)}</title></head>
<body style="margin:0;padding:0;background:#f4f5f7;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f5f7;padding:28px 12px;">
<tr><td align="center">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
         style="max-width:560px;background:#ffffff;border-radius:10px;overflow:hidden;
                font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;
                box-shadow:0 1px 3px rgba(16,24,40,.08);">

    <tr><td style="padding:26px 30px 20px;border-bottom:1px solid #eaecf0;">
      <div style="font-size:19px;font-weight:700;color:#101828;letter-spacing:-.01em;">
        ${escapeHtml(hotel?.name ?? "Restaurant")}
      </div>
      ${hotel?.location ? `<div style="font-size:13px;color:#667085;margin-top:4px;">${escapeHtml(hotel.location)}</div>` : ""}
      ${hotel?.phone ? `<div style="font-size:13px;color:#667085;margin-top:2px;">${escapeHtml(hotel.phone)}</div>` : ""}
      ${gstin ? `<div style="font-size:12px;color:#98a2b3;margin-top:6px;font-family:ui-monospace,Menlo,Consolas,monospace;">GSTIN ${escapeHtml(gstin)}</div>` : ""}
    </td></tr>

    <tr><td style="padding:18px 30px;background:#f9fafb;border-bottom:1px solid #eaecf0;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="font-size:13px;">
        <tr>
          <td style="color:#667085;padding:3px 0;">Invoice</td>
          <td style="text-align:right;color:#101828;font-weight:600;
                     font-family:ui-monospace,Menlo,Consolas,monospace;">
            ${escapeHtml(bill.invoiceNumber ?? String(bill._id).slice(-8).toUpperCase())}
          </td>
        </tr>
        <tr>
          <td style="color:#667085;padding:3px 0;">Date</td>
          <td style="text-align:right;color:#101828;font-weight:600;">
            ${issuedAt.toLocaleDateString("en-IN", { day: "2-digit", month: "short", year: "numeric" })}
            · ${issuedAt.toLocaleTimeString("en-IN", { hour: "2-digit", minute: "2-digit" })}
          </td>
        </tr>
        <tr>
          <td style="color:#667085;padding:3px 0;">Guest</td>
          <td style="text-align:right;color:#101828;font-weight:600;">${escapeHtml(bill.customerName ?? "Guest")}</td>
        </tr>
        <tr>
          <td style="color:#667085;padding:3px 0;">Table</td>
          <td style="text-align:right;color:#101828;font-weight:600;">${escapeHtml(bill.tableId?.sequence ?? "—")}</td>
        </tr>
      </table>
    </td></tr>

    <tr><td style="padding:22px 30px 8px;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
        <thead><tr>
          <th style="text-align:left;font-size:11px;letter-spacing:.08em;text-transform:uppercase;
                     color:#98a2b3;padding-bottom:8px;border-bottom:1px solid #eaecf0;font-weight:600;">Item</th>
          <th style="text-align:center;font-size:11px;letter-spacing:.08em;text-transform:uppercase;
                     color:#98a2b3;padding-bottom:8px;border-bottom:1px solid #eaecf0;font-weight:600;">Qty</th>
          <th style="text-align:right;font-size:11px;letter-spacing:.08em;text-transform:uppercase;
                     color:#98a2b3;padding-bottom:8px;border-bottom:1px solid #eaecf0;font-weight:600;">Rate</th>
          <th style="text-align:right;font-size:11px;letter-spacing:.08em;text-transform:uppercase;
                     color:#98a2b3;padding-bottom:8px;border-bottom:1px solid #eaecf0;font-weight:600;">Amount</th>
        </tr></thead>
        <tbody>${itemRows}</tbody>
      </table>
    </td></tr>

    <tr><td style="padding:14px 30px 24px;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
        ${row("Subtotal", money(bill.subTotal ?? bill.totalAmount, symbol))}
        ${bill.itemDiscount > 0 ? row("Item offers", money(bill.itemDiscount, symbol), { negative: true }) : ""}
        ${bill.offerDiscount > 0 ? row("Bill offer", money(bill.offerDiscount, symbol), { negative: true }) : ""}
        ${bill.customDiscount > 0 ? row("Discount", money(bill.customDiscount, symbol), { negative: true }) : ""}
        ${bill.cgst > 0 ? row("CGST", money(bill.cgst, symbol)) : ""}
        ${bill.sgst > 0 ? row("SGST", money(bill.sgst, symbol)) : ""}
        ${bill.serviceCharge > 0 ? row(`Service charge (${bill.serviceChargePercent}%)`, money(bill.serviceCharge, symbol)) : ""}
        ${bill.roundOff ? row("Round off", money(bill.roundOff, symbol), { muted: true }) : ""}
        <tr><td colspan="2" style="padding-top:8px;border-top:2px solid #101828;"></td></tr>
        ${row("Total", money(bill.finalAmount, symbol), { bold: true })}
        ${
          (bill.payments ?? []).length > 0
            ? bill.payments
                .map((payment) =>
                  row(
                    `Paid · ${payment.method}`,
                    money(payment.amount, symbol),
                    { muted: true }
                  )
                )
                .join("")
            : ""
        }
      </table>
    </td></tr>

    <tr><td style="padding:16px 30px 24px;background:#f9fafb;border-top:1px solid #eaecf0;
                   text-align:center;color:#667085;font-size:13px;">
      ${escapeHtml(hotel?.billing?.footerNote ?? "Thank you for dining with us!")}
    </td></tr>
  </table>
</td></tr></table>
</body></html>`;
};

export default renderInvoiceHtml;
