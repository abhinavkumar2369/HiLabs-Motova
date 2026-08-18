const express = require("express");
const router = express.Router();

const { signup, signin, forgotPassword, verifyResetOtp, resetPassword } = require("../src/controllers/authController");

router.post("/signup", signup);
router.post("/signin", signin);
router.post("/forgot-password", forgotPassword);
router.post("/verify-reset-otp", verifyResetOtp);
router.post("/reset-password", resetPassword);

module.exports = router;
