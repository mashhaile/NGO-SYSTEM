require('dotenv').config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const path = require('path');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

const app = express();

/* ------------------ CONFIG & DB ------------------ */
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/ngo_system";
const JWT_SECRET = process.env.JWT_SECRET || "backup_secret_key_123"; 

// Cloudinary Setup
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_NAME,
  api_key: process.env.CLOUDINARY_KEY,
  api_secret: process.env.CLOUDINARY_SECRET
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'ngo_beneficiaries',
    allowed_formats: ['jpg', 'png', 'pdf']
  },
});
const upload = multer({ storage: storage });

mongoose.connect(MONGO_URI)
  .then(() => console.log("MongoDB Connected ✅"))
  .catch(err => console.error("Database Error ❌:", err.message));

/* ------------------ MIDDLEWARE ------------------ */
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

/* ------------------ MODELS ------------------ */
const Organization = mongoose.model("Organization", { name: { type: String, required: true } });

const User = mongoose.model("User", {
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  organizationId: { type: mongoose.Schema.Types.ObjectId, ref: 'Organization' }
});

const Beneficiary = mongoose.model("Beneficiary", {
  organizationId: { type: mongoose.Schema.Types.ObjectId, ref: 'Organization' },
  name: { type: String, required: true },
  sex: String, age: Number, phone: String, address: String, program: String, details: String,
  photoUrl: String,   // New field for photo link
  idCardUrl: String,  // New field for ID link
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
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (user && await bcrypt.compare(password, user.password)) {
      const token = jwt.sign({ userId: user._id, organizationId: user.organizationId }, JWT_SECRET, { expiresIn: '1d' });
      return res.json({ token });
    }
    res.status(401).json({ message: "Invalid email or password" });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get("/beneficiaries", auth, async (req, res) => {
  const data = await Beneficiary.find({ organizationId: req.user.organizationId });
  res.json(data);
});

// NEW POST ROUTE (Handles text + files)
app.post("/beneficiaries", auth, upload.fields([{ name: 'photo', maxCount: 1 }, { name: 'idCard', maxCount: 1 }]), async (req, res) => {
  try {
    const newData = { 
      ...req.body, 
      organizationId: req.user.organizationId,
      photoUrl: req.files['photo'] ? req.files['photo'][0].path : "",
      idCardUrl: req.files['idCard'] ? req.files['idCard'][0].path : ""
    };
    const saved = await Beneficiary.create(newData);
    res.json(saved);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// UPDATED PUT ROUTE to handle new photos/IDs during editing
app.put('/beneficiaries/:id', auth, upload.fields([{ name: 'photo', maxCount: 1 }, { name: 'idCard', maxCount: 1 }]), async (req, res) => {
    try {
        let updateData = { ...req.body };

        // If new files are uploaded, add their new URLs to the update
        if (req.files['photo']) {
            updateData.photoUrl = req.files['photo'][0].path;
        }
        if (req.files['idCard']) {
            updateData.idCardUrl = req.files['idCard'][0].path;
        }

        const updated = await Beneficiary.findOneAndUpdate(
            { _id: req.params.id, organizationId: req.user.organizationId }, 
            updateData, 
            { returnDocument: 'after' }
        );
        res.json(updated);
    } catch (err) { 
        res.status(400).json({ message: err.message }); 
    }
});

app.delete("/beneficiaries/:id", auth, async (req, res) => {
    await Beneficiary.findOneAndDelete({ _id: req.params.id, organizationId: req.user.organizationId });
    res.json({ message: "Success" });
});

app.get("/stats", auth, async (req, res) => {
    const total = await Beneficiary.countDocuments({ organizationId: req.user.organizationId });
    const programs = await Beneficiary.distinct("program", { organizationId: req.user.organizationId });
    res.json({ totalBeneficiaries: total, totalPrograms: programs.length });
});

app.get("/program-stats", auth, async (req, res) => {
    const stats = await Beneficiary.aggregate([
      { $match: { organizationId: new mongoose.Types.ObjectId(String(req.user.organizationId)) } },
      { $group: { _id: "$program", count: { $sum: 1 } } }
    ]);
    res.json(stats);
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server is flying on port ${PORT}`);
});