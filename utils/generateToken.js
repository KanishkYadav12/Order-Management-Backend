import jwt from "jsonwebauthToken";
export const generateauthToken = (id, role) => {
  return jwt.sign({ id, role }, process.env.JWT_SECRET, { expiresIn: "1d" });
};
