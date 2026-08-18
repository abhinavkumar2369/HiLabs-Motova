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
    subject: "Reset your password",
    html: `<p>Your password reset code is <strong>${otp}</strong>. It expires in ${OTP_EXPIRY_MINUTES} minutes.</p>`,
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

    // 6. Create user in PostgreSQL
    const result = await pool.query(
      `INSERT INTO users
       (name, email, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, name, email, created_at`,
      [name, email, passwordHash]
    );

    const user = result.rows[0];

    // 7. Check JWT secret
    if (!process.env.JWT_SECRET) {
      console.error("JWT_SECRET is not configured");

      return res.status(500).json({
        success: false,
        message: "Server configuration error",
      });
    }

    // 8. Generate JWT token
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

    // 9. Send response
    return res.status(201).json({
      success: true,
      message: "Signup successful",
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

const signin = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required",
      });
    }

    const result = await pool.query(
      `SELECT id, name, email, password_hash
       FROM users
       WHERE email = $1`,
      [email]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password_hash);

    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }

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
      message: "Signin successful",
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
    console.error("Signin error:", error);

    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

// Step 1: user submits email, receives an OTP
const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: "Email is required",
      });
    }

    const result = await pool.query(
      `SELECT id, email
       FROM users
       WHERE email = $1`,
      [email]
    );

    const user = result.rows[0];

    // Do not reveal whether the email exists
    if (!user) {
      return res.status(200).json({
        success: true,
        message: "If that email is registered, an OTP has been sent",
      });
    }

    const otp = generateOtp();
    const otpExpiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);

    await pool.query(
      `UPDATE users
       SET reset_otp_code = $1, reset_otp_expires_at = $2
       WHERE id = $3`,
      [otp, otpExpiresAt, user.id]
    );

    await sendOtpEmail(user.email, otp);

    return res.status(200).json({
      success: true,
      message: "If that email is registered, an OTP has been sent",
    });

  } catch (error) {
    console.error("Forgot password error:", error);

    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

// Step 2: user submits the OTP received; on success gets a short-lived reset token
const verifyResetOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({
        success: false,
        message: "Email and OTP are required",
      });
    }

    const result = await pool.query(
      `SELECT id, reset_otp_code, reset_otp_expires_at
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

    if (
      !user.reset_otp_code ||
      !user.reset_otp_expires_at ||
      new Date(user.reset_otp_expires_at) < new Date()
    ) {
      return res.status(410).json({
        success: false,
        message: "OTP has expired, please request a new one",
      });
    }

    if (user.reset_otp_code !== otp) {
      return res.status(401).json({
        success: false,
        message: "Invalid OTP",
      });
    }

    if (!process.env.JWT_SECRET) {
      console.error("JWT_SECRET is not configured");

      return res.status(500).json({
        success: false,
        message: "Server configuration error",
      });
    }

    // OTP is single-use: clear it now that it has been verified
    await pool.query(
      `UPDATE users
       SET reset_otp_code = NULL, reset_otp_expires_at = NULL
       WHERE id = $1`,
      [user.id]
    );

    const resetToken = jwt.sign(
      {
        userId: user.id,
        purpose: "password_reset",
      },
      process.env.JWT_SECRET,
      {
        expiresIn: `${OTP_EXPIRY_MINUTES}m`,
      }
    );

    return res.status(200).json({
      success: true,
      message: "OTP verified",
      data: {
        reset_token: resetToken,
      },
    });

  } catch (error) {
    console.error("Verify reset OTP error:", error);

    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

// Step 3: user submits the reset token from verify-reset-otp along with the new password
const resetPassword = async (req, res) => {
  try {
    const { resetToken, newPassword } = req.body;

    if (!resetToken || !newPassword) {
      return res.status(400).json({
        success: false,
        message: "Reset token and new password are required",
      });
    }

    if (newPassword.length < 8) {
      return res.status(422).json({
        success: false,
        message: "Password must be at least 8 characters",
      });
    }

    if (!process.env.JWT_SECRET) {
      console.error("JWT_SECRET is not configured");

      return res.status(500).json({
        success: false,
        message: "Server configuration error",
      });
    }

    let payload;
    try {
      payload = jwt.verify(resetToken, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({
        success: false,
        message: "Invalid or expired reset token",
      });
    }

    if (payload.purpose !== "password_reset") {
      return res.status(401).json({
        success: false,
        message: "Invalid reset token",
      });
    }

    const passwordHash = await bcrypt.hash(newPassword, 12);

    const result = await pool.query(
      `UPDATE users
       SET password_hash = $1
       WHERE id = $2
       RETURNING id`,
      [passwordHash, payload.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    return res.status(200).json({
      success: true,
      message: "Password reset successfully",
    });

  } catch (error) {
    console.error("Reset password error:", error);

    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

module.exports = {
  signup,
  signin,
  forgotPassword,
  verifyResetOtp,
  resetPassword,
};
