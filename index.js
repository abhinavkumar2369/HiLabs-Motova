// Importing Express
const express = require("express");


// Cross Origin Site Scripting
const cors = require("cors");
require("dotenv").config();

const authRoutes = require("./routes/userRoutes");


// Instance
const app = express();

app.use(cors());
app.use(express.json());

app.use("/api/v1/auth", authRoutes);


// Route
app.get("/", (req, res) => {
  res.json({ status: "Server running successfully" });
});


// Port
const PORT = process.env.PORT || 5000;


// Terminal
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
