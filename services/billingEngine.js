/**
 * Bill arithmetic.
 *
 * The single rule here: a bill total is a **pure function of its inputs**.
 * `recalculateBill` always recomputes every derived figure from the line
 * items, offers and hotel settings. Nothing is ever incremented in place.
 *
 * The old `updateBillService` did `bill.totalDiscount += parsedDiscount`, so
 * saving a bill twice with a ₹50 discount took ₹100 off. Recomputing from
 * scratch makes that class of bug impossible.
 */

/** Rounds to 2 decimal places without binary-float drift on .005 cases. */
export const round2 = (value) =>
  Math.round((Number(value) + Number.EPSILON) * 100) / 100;

/**
 * Discount contributed by a dish-level offer, for one line.
 * Returns 0 when the offer is missing, disabled, or outside its date window.
 */
export const calculateItemDiscount = (dish, quantity, at = new Date()) => {
  const offer = dish?.offer;
  if (!offer || offer.disable) return 0;

  if (offer.startDate && at < new Date(offer.startDate)) return 0;
  if (offer.endDate && at > new Date(offer.endDate)) return 0;

  const lineValue = (dish.price ?? 0) * quantity;

  const discount =
    offer.discountType === "percent"
      ? (lineValue * offer.value) / 100
      : offer.value * quantity;

  // An offer can never exceed the value of the line it applies to.
  return round2(Math.min(discount, lineValue));
};

/**
 * Discount contributed by a bill-level ("global") offer.
 *
 * @param {object} offer
 * @param {number} base  Amount the offer applies to, after item discounts.
 */
export const calculateGlobalDiscount = (offer, base, at = new Date()) => {
  if (!offer || offer.disable) return 0;
  if (offer.type !== "global") return 0;
  if (offer.appliedAbove && base < offer.appliedAbove) return 0;
  if (offer.startDate && at < new Date(offer.startDate)) return 0;
  if (offer.endDate && at > new Date(offer.endDate)) return 0;

  const discount =
    offer.discountType === "percent"
      ? (base * offer.value) / 100
      : offer.value;

  return round2(Math.min(discount, base));
};

/**
 * Recomputes every monetary field on a bill.
 *
 * @param {object} params
 * @param {Array}  params.items   [{ dish, quantity }] — `dish` populated with `offer`
 * @param {object} [params.globalOffer]
 * @param {number} [params.customDiscount]
 * @param {object} params.billingSettings  hotel.billing
 * @returns {object} every derived figure, ready to assign onto the bill
 */
export const recalculateBill = ({
  items = [],
  globalOffer = null,
  customDiscount = 0,
  billingSettings = {},
  at = new Date(),
}) => {
  const {
    taxRatePercent: defaultTaxRate = 5,
    pricesIncludeTax = false,
    serviceChargePercent = 0,
    roundOffEnabled = true,
  } = billingSettings;

  const lineItems = [];
  let subTotal = 0;
  let itemDiscount = 0;

  for (const { dish, quantity } of items) {
    if (!dish || !quantity) continue;

    const unitPrice = dish.price ?? 0;
    const lineValue = round2(unitPrice * quantity);
    const discount = calculateItemDiscount(dish, quantity, at);

    subTotal += lineValue;
    itemDiscount += discount;

    lineItems.push({
      dishId: dish._id,
      name: dish.name,
      quantity,
      unitPrice,
      discount,
      // A dish may override the restaurant's default rate.
      taxRatePercent: dish.taxRatePercent ?? defaultTaxRate,
      lineTotal: round2(lineValue - discount),
    });
  }

  subTotal = round2(subTotal);
  itemDiscount = round2(itemDiscount);

  const afterItemDiscount = round2(subTotal - itemDiscount);
  const offerDiscount = calculateGlobalDiscount(
    globalOffer,
    afterItemDiscount,
    at
  );

  // A manual discount can never take the bill below zero.
  const manualDiscount = round2(
    Math.max(0, Math.min(Number(customDiscount) || 0, afterItemDiscount - offerDiscount))
  );

  const totalDiscount = round2(itemDiscount + offerDiscount + manualDiscount);
  const netAmount = round2(subTotal - totalDiscount);

  /* Tax.
     Bill-level discounts are apportioned across lines by value so each line
     is taxed on what was actually charged for it. */
  const discountAfterItems = round2(offerDiscount + manualDiscount);
  const apportionBase = afterItemDiscount || 1;

  let taxableAmount = 0;
  let totalTax = 0;

  for (const line of lineItems) {
    const share = line.lineTotal / apportionBase;
    const lineNet = round2(line.lineTotal - discountAfterItems * share);
    const rate = line.taxRatePercent ?? 0;

    if (pricesIncludeTax) {
      // Price already contains tax: extract rather than add.
      const base = round2(lineNet / (1 + rate / 100));
      taxableAmount += base;
      totalTax += round2(lineNet - base);
    } else {
      taxableAmount += lineNet;
      totalTax += round2((lineNet * rate) / 100);
    }
  }

  taxableAmount = round2(taxableAmount);
  totalTax = round2(totalTax);

  // GST is presented as an equal CGST/SGST split on an intra-state invoice.
  const cgst = round2(totalTax / 2);
  const sgst = round2(totalTax - cgst);

  const serviceCharge = round2((netAmount * serviceChargePercent) / 100);

  const payableBeforeRounding = pricesIncludeTax
    ? round2(netAmount + serviceCharge)
    : round2(netAmount + totalTax + serviceCharge);

  const finalAmount = roundOffEnabled
    ? Math.round(payableBeforeRounding)
    : payableBeforeRounding;

  const roundOff = round2(finalAmount - payableBeforeRounding);

  return {
    orderedItems: lineItems,
    subTotal,
    totalAmount: subTotal, // legacy alias read by existing screens
    itemDiscount,
    offerDiscount,
    customDiscount: manualDiscount,
    totalDiscount,
    taxableAmount,
    cgst,
    sgst,
    totalTax,
    serviceChargePercent,
    serviceCharge,
    roundOff,
    finalAmount: Math.max(0, finalAmount),
  };
};

/**
 * Next invoice number for a restaurant, e.g. `INV/2026-27/0042`.
 *
 * The financial year runs April–March, which is what an Indian accountant
 * will expect to see on the sequence.
 */
export const formatInvoiceNumber = (prefix, counter, at = new Date()) => {
  const year = at.getMonth() >= 3 ? at.getFullYear() : at.getFullYear() - 1;
  const fy = `${year}-${String((year + 1) % 100).padStart(2, "0")}`;
  return `${prefix || "INV"}/${fy}/${String(counter).padStart(4, "0")}`;
};
