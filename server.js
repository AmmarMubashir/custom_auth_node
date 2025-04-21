require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const cors = require("cors");

const app = express();
app.use(
  cors({
    origin: "YOUR_LOCALHOST_URL", // for local host testing
    // origin: "YOUR_FRONTNED_URL", // for production
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  })
);

app.use(express.json());

// MongoDB User Model
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  resetToken: String,
  resetTokenExpiration: Date,
});

const User = mongoose.model("User", userSchema);

// Welcome Route
app.get("/api/welcome", (req, res) => {
  res.json({ message: "Welcome to our API!" });
});

// Signup Route
app.post("/api/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const exists = await User.findOne({ email });
    if (exists)
      return res.status(400).json({ message: "Email already registered" });

    const hashed = await bcrypt.hash(password, 12);
    const user = new User({ name, email, password: hashed });
    await user.save();

    res.json({ message: "User registered successfully" });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Login Route
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });
    res.json({ token, message: "User login successfully" });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

app.post("/api/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) return res.status(400).json({ message: "User not found" });

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "15m",
    });

    user.resetToken = token;
    user.resetTokenExpiration = Date.now() + 15 * 60 * 1000;
    await user.save();

    // const resetLink = `YOUR_FRONTEND_URL/resetpasswordpage.html?token=${token}`; // Update this to your frontend URL (this is for production)
    const resetLink = `YOUR_LOCALHOST_URL/resetpasswordpage.html?token=${token}`; // Update this to your frontend URL (this is for local host)

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const plainText = `Hello ${
      user.name || "User"
    },\n\nYou requested a password reset for your {YOUR_WEBSITE_NAME} account.\n\nReset your password here: ${resetLink}\n\nIf you didn't request this, just ignore this email.\n\n© ${new Date().getFullYear()} {YOUR_WEBSITE_NAME}`;

    const htmlContent = `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="UTF-8">
          <title>Password Reset</title>
        </head>
        <body style="font-family: Arial, sans-serif; background-color: #f9f9f9; color: #333; padding: 20px;">
          <div style="max-width: 600px; margin: auto; background-color: #fff; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1);">
            <h2>Password Reset Request</h2>
            <p>Hello ${user.name || "there"},</p>
            <p>We received a request to reset your password for your {YOUR_WEBSITTE_NAME} account.</p>
            <p style="text-align: center; margin: 30px 0;">
              <a href="${resetLink}" style="padding: 12px 25px; background-color: #d4a373; color: white; text-decoration: none; border-radius: 5px;">
                Reset Password
              </a>
            </p>
            <p>If you didn’t request a password reset, please ignore this email.</p>
            <hr />
            <p style="font-size: 12px; color: #999;">© ${new Date().getFullYear()} {YOUR_WEBSITTE_NAME}. All rights reserved.</p>
          </div>
        </body>
      </html>
    `;

    await transporter.sendMail({
      from: `"{YOUR_WEBSITE_NAME} Support" <${process.env.EMAIL_USER}>`, // sender email must match Gmail account
      to: email,
      replyTo: process.env.EMAIL_USER,
      subject: "Reset Your Password - {YOUR_WEBSITE_NAME}",
      text: plainText,
      html: htmlContent,
    });

    res.json({ message: "Password reset link sent to your email." });
  } catch (err) {
    console.error("Error in forgot-password:", err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Reset Password Route
app.post("/api/reset-password", async (req, res) => {
  try {
    const { token, password } = req.body;

    if (!token || !password) {
      return res
        .status(400)
        .json({ message: "Token and password are required." });
    }

    // Verify the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Find the user by ID and check token expiration
    const user = await User.findOne({
      _id: decoded.userId,
      resetToken: token,
      resetTokenExpiration: { $gt: Date.now() }, // not expired
    });

    if (!user) {
      return res.status(400).json({ message: "Invalid or expired token." });
    }

    // Hash the new password and save it
    const hashedPassword = await bcrypt.hash(password, 12);
    user.password = hashedPassword;

    // Clear reset token fields
    user.resetToken = undefined;
    user.resetTokenExpiration = undefined;

    await user.save();

    res.json({ message: "Password has been reset successfully." });
  } catch (err) {
    console.error("Reset Password Error:", err);
    res.status(400).json({ message: "Invalid or expired token." });
  }
});

app.post("/api/contact-us", async (req, res) => {
  try {
    const { name, email, message } = req.body;

    if (!name || !email || !message) {
      return res.status(400).json({ message: "All fields are required." });
    }

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const plainText = `You have a new contact form submission:\n\nName: ${name}\nEmail: ${email}\nMessage:\n${message}`;

    const htmlContent = `
      <div style="font-family: Arial, sans-serif; color: #333;">
        <h2>New Contact Form Submission</h2>
        <p><strong>Name:</strong> ${name}</p>
        <p><strong>Email:</strong> ${email}</p>
        <p><strong>Message:</strong></p>
        <p>${message.replace(/\n/g, "<br>")}</p>
        <hr>
        <p style="font-size: 12px; color: #999;">© ${new Date().getFullYear()} {YOUR_WEBSITE_NAME}. All rights reserved.</p>
      </div>
    `;

    await transporter.sendMail({
      from: `"Contact Form" <${process.env.EMAIL_USER}>`,
      to: process.env.EMAIL_USER, // send to yourself
      replyTo: email,
      subject: `New Contact Message from ${name}`,
      text: plainText,
      html: htmlContent,
    });

    res.status(200).json({ message: "Message sent successfully!" });
  } catch (err) {
    console.error("Error in contact-us:", err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

app.get("/api/users", async (req, res) => {
  try {
    const users = await User.find({});
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Connect to MongoDB and Start Server
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    app.listen(process.env.PORT, () => {
      console.log(`Server running on http://localhost:${process.env.PORT}`);
    });
  })
  .catch((err) => console.error("MongoDB connection failed:", err));
