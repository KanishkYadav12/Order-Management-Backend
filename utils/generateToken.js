import jwt from "jsonwebtoken";

const SECRET = process.env.ACCESS_TOKEN_SECRET;
const EXPIRES = process.env.ACCESS_TOKEN_EXPIRES || "30d";

if (!SECRET) {
  console.warn("ACCESS_TOKEN_SECRET is not set. Set it in your .env file.");
}

export function generatetoken(userId, role) {
  const payload = { sub: userId.toString(), role }; // keep it small
  return jwt.sign(payload, SECRET, { expiresIn: EXPIRES });
}
