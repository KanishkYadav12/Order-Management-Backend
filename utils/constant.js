export const ROLES = {
  SUPER_ADMIN: "superadmin",
  HOTEL_OWNER: "hotelowner",
};

export const isValidRole = (role) => {
  if (typeof role !== "string") {
    throw new Error("Role must be a string");
  }
  return Object.values(ROLES).includes(role);
};
