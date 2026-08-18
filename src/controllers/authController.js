const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const pool = require("../config/db");
const resend = require("../config/resend");

const OTP_EXPIRY_MINUTES = 10;

const generateOtp = () =>
  String(Math.floor(100000 + Math.random() * 900000));

const sendOtpEmail = async (email, otp) => {
  await resend.emails.send({
    from: process.env.RESEND_FROM_EMAIL,
    to: email,
    subject: "Verify your email",
    html: `<p>Your verification code is <strong>${otp}</strong>. It expires in ${OTP_EXPIRY_MINUTES} minutes.</p>`,
  });
};

const signup = async (req, res) => {
  try {
    // 1. Get data from request body
    const { name, email, password } = req.body;

    // 2. Validate required fields
    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "Name, email and password are required",
      });
    }

    // 3. Validate password length
    if (password.length < 8) {
      return res.status(422).json({
        success: false,
        message: "Password must be at least 8 characters",
      });
    }

    // 4. Check if email already exists
    const existingUser = await pool.query(
      `SELECT id
       FROM users
       WHERE email = $1`,
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({
        success: false,
        message: "Email already registered",
      });
    }

    // 5. Hash password
    const passwordHash = await bcrypt.hash(password, 12);

    // 6. Generate OTP
    const otp = generateOtp();
    const otpExpiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);

    // 7. Create user in PostgreSQL (unverified, with OTP)
    const result = await pool.query(
      `INSERT INTO users
       (name, email, password_hash, otp_code, otp_expires_at)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, name, email, created_at`,
      [name, email, passwordHash, otp, otpExpiresAt]
    );

    const user = result.rows[0];

    // 8. Send OTP email via Resend
    await sendOtpEmail(user.email, otp);

    // 9. Send response (no access token until OTP is verified)
    return res.status(201).json({
      success: true,
      message: "Signup successful. Please verify the OTP sent to your email",
      data: {
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
        },
      },
    });

  } catch (error) {
    console.error("Signup error:", error);

    // Handle PostgreSQL duplicate email race condition
    if (error.code === "23505") {
      return res.status(409).json({
        success: false,
        message: "Email already registered",
      });
    }

    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

const verifyOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({
        success: false,
        message: "Email and OTP are required",
      });
    }

    const result = await pool.query(
      `SELECT id, name, email, otp_code, otp_expires_at, is_verified
       FROM users
       WHERE email = $1`,
      [email]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    if (user.is_verified) {
      return res.status(409).json({
        success: false,
        message: "Email already verified",
      });
    }

    if (!user.otp_code || !user.otp_expires_at || new Date(user.otp_expires_at) < new Date()) {
      return res.status(410).json({
        success: false,
        message: "OTP has expired, please request a new one",
      });
    }

    if (user.otp_code !== otp) {
      return res.status(401).json({
        success: false,
        message: "Invalid OTP",
      });
    }

    await pool.query(
      `UPDATE users
       SET is_verified = TRUE, otp_code = NULL, otp_expires_at = NULL
       WHERE id = $1`,
      [user.id]
    );

    if (!process.env.JWT_SECRET) {
      console.error("JWT_SECRET is not configured");

      return res.status(500).json({
        success: false,
        message: "Server configuration error",
      });
    }

    const accessToken = jwt.sign(
      {
        userId: user.id,
        email: user.email,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: process.env.JWT_EXPIRES_IN || "1h",
      }
    );

    return res.status(200).json({
      success: true,
      message: "Email verified successfully",
      data: {
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
        },
        access_token: accessToken,
      },
    });

  } catch (error) {
    console.error("OTP verification error:", error);

    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

const resendOtp = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: "Email is required",
      });
    }

    const result = await pool.query(
      `SELECT id, email, is_verified
       FROM users
       WHERE email = $1`,
      [email]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    if (user.is_verified) {
      return res.status(409).json({
        success: false,
        message: "Email already verified",
      });
    }

    const otp = generateOtp();
    const otpExpiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);

    await pool.query(
      `UPDATE users
       SET otp_code = $1, otp_expires_at = $2
       WHERE id = $3`,
      [otp, otpExpiresAt, user.id]
    );

    await sendOtpEmail(user.email, otp);

    return res.status(200).json({
      success: true,
      message: "OTP resent successfully",
    });

  } catch (error) {
    console.error("Resend OTP error:", error);

    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

module.exports = {
  signup,
  verifyOtp,
  resendOtp,
};