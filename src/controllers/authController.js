const bcrypt = require("bcryptjs");
const pool = require("../config/db");

// POST /api/v1/auth/signup
async function signup(req, res) {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ success: false, message: "All fields are required" });
  }

  try {
    const existing = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [email]
    );
    if (existing.rows.length > 0) {
      return res.status(409).json({ success: false, message: "Email already registered" });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users
      (name, email, password_hash)
      VALUES ($1, $2, $3)
      RETURNING id, name, email, created_at`,
      [name, email, passwordHash]
    );
    const user = result.rows[0];

    return res.status(201).json({
      success: true,
      message: "Signup successful",
      user: { id: user.id, name: user.name, email: user.email, phoneNumber: user.phone_number },
    });
  } catch (err) {
    console.error("Signup error:", err);
    return res.status(500).json({ success: false, message: "Something went wrong" });
  }
}

module.exports = { signup };
