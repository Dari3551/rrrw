import jwt from "jsonwebtoken";

export function signToken(user) {
  return jwt.sign({ uid: user.id }, process.env.JWT_SECRET, { expiresIn: "7d" });
}

export function authMiddleware(req, res, next) {
  const hdr = req.headers.authorization || "";
  const token = hdr.startsWith("Bearer ") ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ error: "unauthorized" });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "unauthorized" });
  }
}