/**
 * Roles.
 *
 * The system has exactly two kinds of user:
 *
 *   superadmin  Runs the platform. Onboards and manages restaurants, never
 *               works a service. Has no hotel of their own.
 *   hotelowner  Runs one restaurant. Everything operational happens here.
 *
 * Both values are unchanged from the original system, so existing accounts
 * and tokens stay valid.
 */
export const ROLES = {
  SUPER_ADMIN: "superadmin",
  HOTEL_OWNER: "hotelowner",
};

/** Roles that belong to a restaurant rather than to the platform. */
export const TENANT_ROLES = [ROLES.HOTEL_OWNER];

export const isValidRole = (role) =>
  typeof role === "string" && Object.values(ROLES).includes(role);

/** Both roles can self-register; an admin additionally needs a dev key. */
export const SELF_SIGNUP_ROLES = [ROLES.SUPER_ADMIN, ROLES.HOTEL_OWNER];

/**
 * Permissions.
 *
 * With two roles this is not strictly load-bearing — an owner can do
 * everything inside their restaurant. It stays because routes read far better
 * declaring what they need (`authorize(PERMISSIONS.BILL_PAY)`) than repeating
 * a role name, and because adding staff roles later becomes a table edit
 * rather than a sweep through every router.
 */
export const PERMISSIONS = {
  MENU_READ: "menu:read",
  MENU_WRITE: "menu:write",
  TABLE_READ: "table:read",
  TABLE_WRITE: "table:write",
  ORDER_READ: "order:read",
  ORDER_WRITE: "order:write",
  ORDER_STATUS: "order:status",
  ORDER_DELETE: "order:delete",
  BILL_READ: "bill:read",
  BILL_WRITE: "bill:write",
  BILL_PAY: "bill:pay",
  BILL_DISCOUNT: "bill:discount",
  BILL_DELETE: "bill:delete",
  DASHBOARD_READ: "dashboard:read",
  REPORT_READ: "report:read",
  HOTEL_SETTINGS: "hotel:settings",
  AI_USE: "ai:use",
};

const ALL_PERMISSIONS = Object.values(PERMISSIONS);

export const ROLE_PERMISSIONS = Object.freeze({
  [ROLES.HOTEL_OWNER]: ALL_PERMISSIONS,
  [ROLES.SUPER_ADMIN]: ALL_PERMISSIONS,
});

export const hasPermission = (role, permission) =>
  (ROLE_PERMISSIONS[role] ?? []).includes(permission);

export const ORDER_STATUS = {
  DRAFT: "draft",
  PENDING: "pending",
  PREPARING: "preparing",
  READY: "ready",
  COMPLETED: "completed",
  CANCELLED: "cancelled",
};

export const BILL_STATUS = {
  UNPAID: "unpaid",
  PAID: "paid",
  PAY_LATER: "payLater",
  REFUNDED: "refunded",
  VOID: "void",
};

export const PAYMENT_METHODS = {
  CASH: "cash",
  CARD: "card",
  UPI: "upi",
  WALLET: "wallet",
  OTHER: "other",
};

export const TABLE_STATUS = {
  FREE: "free",
  OCCUPIED: "occupied",
  RESERVED: "reserved",
  CLEANING: "cleaning",
};
