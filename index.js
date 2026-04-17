require('dotenv').config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
app.use(cors());
app.use(express.json());
/* ------------------ CONFIG & DB ------------------ */
// FIX: This ensures your secret key always has a value
const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/ngo_system";
const JWT_SECRET = process.env.JWT_SECRET || "backup_secret_key_123"; 

mongoose.connect(MONGO_URI)
  .then(() => console.log("MongoDB Connected ✅"))
  .catch(err => console.error("Database Error ❌:", err.message));

/* ------------------ MODELS ------------------ */
const Organization = mongoose.model("Organization", {
  name: { type: String, required: true }
});

const User = mongoose.model("User", {
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  organizationId: { type: mongoose.Schema.Types.ObjectId, ref: 'Organization' }
});

// index.js
// This tells the database how to store a Beneficiary record
const Beneficiary = mongoose.model("Beneficiary", {
  // Links this person to a specific NGO/Organization
  organizationId: { type: mongoose.Schema.Types.ObjectId, ref: 'Organization' },
  
  // Basic Information
  name: { type: String, required: true }, // Name is required
  sex: String,                            // Male / Female
  age: Number,                            // Store as a number for calculations
  
  // Contact & Location
  phone: String,                          // Phone number
  address: String,                        // Physical location
  
  // Project Data
  program: String,                        // Which NGO program they belong to
  details: String,                        // Long text for medical history/case notes
  
  // Automatically record when they were registered
  createdAt: { type: Date, default: Date.now }
});

/* ------------------ AUTH MIDDLEWARE ------------------ */
const auth = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1]; 

  if (!token) return res.status(401).json({ message: "No token provided" });

  try {
    // FIX: Using the JWT_SECRET variable we defined above
    const decoded = jwt.verify(token, JWT_SECRET); 
    req.user = decoded; 
    next();
  } catch (err) {
    res.status(403).json({ message: "Invalid or Expired Token" });
  }
};

/* ------------------ ROUTES ------------------ */

app.post("/register", async (req, res) => {
  try {
    const { orgName, email, password } = req.body;
    const org = await Organization.create({ name: orgName });
    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ email, password: hashedPassword, organizationId: org._id });
    res.json({ message: "Registration successful!" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (user && await bcrypt.compare(password, user.password)) {
      // FIX: Using the JWT_SECRET variable we defined above
      const token = jwt.sign(
        { userId: user._id, organizationId: user.organizationId },
        JWT_SECRET, 
        { expiresIn: '1d' }
      );
      return res.json({ token });
    }
    res.status(401).json({ message: "Invalid email or password" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/beneficiaries", auth, async (req, res) => {
  const data = await Beneficiary.find({ organizationId: req.user.organizationId });
  res.json(data);
});

app.post("/beneficiaries", auth, async (req, res) => {
  // Force the organizationId to come from the TOKEN, not the user's input
  const newData = { ...req.body, organizationId: req.user.organizationId };
  const saved = await Beneficiary.create(newData);
  res.json(saved);
});

// Update a Beneficiary
app.put("/beneficiaries/:id", auth, async (req, res) => {
  try {
    const updated = await Beneficiary.findOneAndUpdate(
      { _id: req.params.id, organizationId: req.user.organizationId }, // Security: Must own the record
      req.body,
      { new: true }
    );
    res.json(updated);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
//Aggregation
app.get("/program-stats", auth, async (req, res) => {
  try {
    const stats = await Beneficiary.aggregate([
      // 1. Only look at data for YOUR NGO
      { $match: { organizationId: new mongoose.Types.ObjectId(req.user.organizationId) } },
      // 2. Group them by program name and count them
      { $group: { _id: "$program", count: { $sum: 1 } } }
    ]);
    res.json(stats);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete a Beneficiary
app.delete("/beneficiaries/:id", auth, async (req, res) => {
    try {
        await Beneficiary.findOneAndDelete({ 
            _id: req.params.id, 
            organizationId: req.user.organizationId 
        });
        res.json({ message: "Success" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
app.get("/stats", auth, async (req, res) => {
  const total = await Beneficiary.countDocuments({ organizationId: req.user.organizationId });
  const programs = await Beneficiary.distinct("program", { organizationId: req.user.organizationId });
  res.json({ totalBeneficiaries: total, totalPrograms: programs.length });
});

app.get("/program-stats", auth, async (req, res) => {
  const stats = await Beneficiary.aggregate([
    { $match: { organizationId: new mongoose.Types.ObjectId(req.user.organizationId) } },
    { $group: { _id: "$program", count: { $sum: 1 } } }
  ]);
  res.json(stats);
});

// This tells the app: Use Render's port, but if running on my PC, use 5000
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
