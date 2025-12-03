import jwt from "jsonwebtoken";
export const generatetoken = (id, role) => {
  return jwt.sign({ id, role }, process.env.JWT_SECRET, { expiresIn: "1d" });
};
