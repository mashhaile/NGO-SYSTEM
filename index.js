require('dotenv').config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const path = require('path');

const app = express();

/* ------------------ CONFIG & DB ------------------ */
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/ngo_system";
const JWT_SECRET = process.env.JWT_SECRET || "backup_secret_key_123"; 

mongoose.connect(MONGO_URI)
  .then(() => console.log("MongoDB Connected ✅"))
  .catch(err => console.error("Database Error ❌:", err.message));

/* ------------------ MIDDLEWARE ------------------ */
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

/* ------------------ MODELS ------------------ */
const Organization = mongoose.model("Organization", {
  name: { type: String, required: true }
});

const User = mongoose.model("User", {
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  organizationId: { type: mongoose.Schema.Types.ObjectId, ref: 'Organization' }
});

const Beneficiary = mongoose.model("Beneficiary", {
  organizationId: { type: mongoose.Schema.Types.ObjectId, ref: 'Organization' },
  name: { type: String, required: true },
  sex: String,
  age: Number,
  phone: String,
  address: String,
  program: String,
  details: String,
  createdAt: { type: Date, default: Date.now }
});

/* ------------------ AUTH MIDDLEWARE ------------------ */
const auth = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1]; 

  if (!token) return res.status(401).json({ message: "No token provided" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET); 
    req.user = decoded; 
    next();
  } catch (err) {
    res.status(403).json({ message: "Invalid or Expired Token" });
  }
};

/* ------------------ API ROUTES ------------------ */

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
  try {
    const data = await Beneficiary.find({ organizationId: req.user.organizationId });
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/beneficiaries", auth, async (req, res) => {
  try {
    const newData = { ...req.body, organizationId: req.user.organizationId };
    const saved = await Beneficiary.create(newData);
    res.json(saved);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put("/beneficiaries/:id", auth, async (req, res) => {
  try {
    const updated = await Beneficiary.findOneAndUpdate(
      { _id: req.params.id, organizationId: req.user.organizationId },
      req.body,
      { new: true }
    );
    res.json(updated);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

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
  try {
    const total = await Beneficiary.countDocuments({ organizationId: req.user.organizationId });
    const programs = await Beneficiary.distinct("program", { organizationId: req.user.organizationId });
    res.json({ totalBeneficiaries: total, totalPrograms: programs.length });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/program-stats", auth, async (req, res) => {
  try {
    const stats = await Beneficiary.aggregate([
      { $match: { organizationId: new mongoose.Types.ObjectId(req.user.organizationId) } },
      { $group: { _id: "$program", count: { $sum: 1 } } }
    ]);
    res.json(stats);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/* ------------------ FRONTEND ROUTING ------------------ */

// Home route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Catch-all for other pages
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

/* ------------------ START SERVER ------------------ */
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});