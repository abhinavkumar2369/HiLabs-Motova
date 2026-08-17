const bcrypt = require("bcryptjs");
const pool = require("../config/db");

// POST /api/v1/auth/signup
async function signup(req, res) {
  const { name, email, phoneNumber, password } = req.body;

  if (!name || !email || !phoneNumber || !password) {
    return res.status(400).json({ success: false, message: "All fields are required" });
  }

  try {
    const existing = await pool.query(
      "SELECT id FROM users WHERE email = $1 OR phone_number = $2",
      [email, phoneNumber]
    );
    if (existing.rows.length > 0) {
      return res.status(409).json({ success: false, message: "Email or phone number already registered" });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users (name, email, phone_number, password_hash)
       VALUES ($1, $2, $3, $4) RETURNING id, name, email, phone_number`,
      [name, email, phoneNumber, passwordHash]
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
