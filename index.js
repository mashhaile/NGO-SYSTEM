require('dotenv').config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const path = require("path");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const { CloudinaryStorage } = require("multer-storage-cloudinary");

const app = express();

/* ------------------ CONFIG & DB ------------------ */
const PORT = process.env.PORT || 5000;
const MONGO_URI =
  process.env.MONGO_URI || "mongodb://127.0.0.1:27017/ngo_system";
const JWT_SECRET =
  process.env.JWT_SECRET || "backup_secret_key_123";

// Cloudinary Setup (only used if environment variables are provided)
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_NAME,
  api_key: process.env.CLOUDINARY_KEY,
  api_secret: process.env.CLOUDINARY_SECRET,
});

// Configure storage
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: "ngo_beneficiaries",
    allowed_formats: ["jpg", "jpeg", "png", "pdf"],
  },
});

const upload = multer({ storage });

// Connect to MongoDB
mongoose
  .connect(MONGO_URI)
  .then(() => console.log("MongoDB Connected ✅"))
  .catch((err) => console.error("Database Error ❌:", err.message));

/* ------------------ MIDDLEWARE ------------------ */
app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname)));

/* ------------------ MODELS ------------------ */

// Organization
const Organization = mongoose.model(
  "Organization",
  new mongoose.Schema({
    name: { type: String, required: true },
  })
);

// User
const User = mongoose.model(
  "User",
  new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    organizationId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Organization",
    },
  })
);

// Beneficiary
const Beneficiary = mongoose.model(
  "Beneficiary",
  new mongoose.Schema({
    organizationId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Organization",
    },
    name: { type: String, required: true },
    sex: String,
    age: Number,
    phone: String,
    address: String,
    program: String,
    category: String, // student, teacher, etc.
    details: String,
    photoUrl: String,
    idCardUrl: String,
    createdAt: { type: Date, default: Date.now },
  })
);

// Program
const Program = mongoose.model(
  "Program",
  new mongoose.Schema({
    name: { type: String, required: true },
    description: String,
    startDate: Date,
    status: {
      type: String,
      enum: ["Active", "Completed", "Planned"],
      default: "Active",
    },
    organizationId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Organization",
    },
  })
);

// Training
const Training = mongoose.model(
  "Training",
  new mongoose.Schema({
    organizationId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Organization",
    },

    title: { type: String, required: true },
    category: String,
    dateRange: String,

    // ADD THESE THREE FIELDS
    male: {
      type: Number,
      default: 0,
    },

    female: {
      type: Number,
      default: 0,
    },

    total: {
      type: Number,
      default: 0,
    },

    status: {
      type: String,
      default: "Completed",
    },

    participants: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Beneficiary",
      },
    ],

    createdAt: {
      type: Date,
      default: Date.now,
    },
  })
);

/* ------------------ AUTH MIDDLEWARE ------------------ */
const auth = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(403).json({ message: "Invalid or Expired Token" });
  }
};

/* ------------------ API ROUTES ------------------ */

// Register
app.post("/register", async (req, res) => {
  try {
    const { orgName, email, password } = req.body;

    const org = await Organization.create({ name: orgName });
    const hashedPassword = await bcrypt.hash(password, 10);

    await User.create({
      email,
      password: hashedPassword,
      organizationId: org._id,
    });

    res.json({ message: "Registration successful!" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (user && (await bcrypt.compare(password, user.password))) {
      const token = jwt.sign(
        {
          userId: user._id,
          organizationId: user.organizationId,
        },
        JWT_SECRET,
        { expiresIn: "1d" }
      );

      return res.json({ token });
    }

    res.status(401).json({ message: "Invalid email or password" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/* ------------------ BENEFICIARIES ------------------ */

// Get beneficiaries
app.get("/beneficiaries", auth, async (req, res) => {
  try {
    const data = await Beneficiary.find({
      organizationId: req.user.organizationId,
    });
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create beneficiary
app.post(
  "/beneficiaries",
  auth,
  upload.fields([
    { name: "photo", maxCount: 1 },
    { name: "idCard", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const files = req.files || {};

      const newData = {
        ...req.body,
        organizationId: req.user.organizationId,
        photoUrl:
          files.photo && files.photo[0]
            ? files.photo[0].path
            : "",
        idCardUrl:
          files.idCard && files.idCard[0]
            ? files.idCard[0].path
            : "",
      };

      const saved = await Beneficiary.create(newData);
      res.json(saved);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

// Update beneficiary
app.put(
  "/beneficiaries/:id",
  auth,
  upload.fields([
    { name: "photo", maxCount: 1 },
    { name: "idCard", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const files = req.files || {};
      const updateData = { ...req.body };

      if (files.photo && files.photo[0]) {
        updateData.photoUrl = files.photo[0].path;
      }

      if (files.idCard && files.idCard[0]) {
        updateData.idCardUrl = files.idCard[0].path;
      }

      const updated = await Beneficiary.findOneAndUpdate(
        {
          _id: req.params.id,
          organizationId: req.user.organizationId,
        },
        updateData,
        {
          new: true,
          runValidators: true,
        }
      );

      res.json(updated);
    } catch (err) {
      res.status(400).json({ message: err.message });
    }
  }
);

// Delete beneficiary
app.delete("/beneficiaries/:id", auth, async (req, res) => {
  try {
    await Beneficiary.findOneAndDelete({
      _id: req.params.id,
      organizationId: req.user.organizationId,
    });

    res.json({ message: "Success" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/* ------------------ PROGRAMS ------------------ */

// Get programs
app.get("/programs", auth, async (req, res) => {
  try {
    const programs = await Program.find({
      organizationId: req.user.organizationId,
    });

    res.json(programs);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create program
app.post("/programs", auth, async (req, res) => {
  try {
    const program = new Program({
      ...req.body,
      organizationId: req.user.organizationId,
    });

    await program.save();
    res.status(201).json(program);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/* ------------------ TRAININGS ------------------ */

// Create training (FIXED)
// --- TRAININGS ---
app.post('/trainings', auth, async (req, res) => {
    try {
        console.log("Incoming training payload:", req.body);

        // Convert participants to valid ObjectId strings only
        const participants = (req.body.participants || [])
            .map(p => {
                // If frontend sends a string: "69fe24555e10c32988648f14"
                if (typeof p === "string") return p;

                // If frontend sends an object:
                // { id: "...", name: "John Doe" }
                // or { _id: "...", name: "John Doe" }
                if (p && typeof p === "object") {
                    return p.id || p._id;
                }

                return null;
            })
            .filter(id =>
                id &&
                mongoose.Types.ObjectId.isValid(id)
            );

        const male = Number(req.body.male) || 0;
        const female = Number(req.body.female) || 0;
        const total = male + female;

        const training = new Training({
            organizationId: req.user.organizationId,
            title: req.body.title,
            category: req.body.category || "",
            dateRange: req.body.dateRange || "",
            male,
            female,
            total,
            status: req.body.status || "Completed",
            participants
        });

        await training.save();

        // Return populated participants so names are available immediately
        const savedTraining = await Training.findById(training._id)
            .populate('participants');

        res.status(201).json(savedTraining);

    } catch (err) {
        console.error("Training save error:", err);

        res.status(500).json({
            message: "Error saving training",
            error: err.message
        });
    }
});
// Update training
app.put("/trainings/:id", auth, async (req, res) => {
  try {
    // Convert participant objects to ObjectIds
    const participants = (req.body.participants || [])
      .map(p => {
        if (typeof p === "string") return p;
        if (p && typeof p === "object") return p.id || p._id;
        return null;
      })
      .filter(id =>
        id && mongoose.Types.ObjectId.isValid(id)
      );

    // Read counts
    const male = Number(req.body.male) || 0;
    const female = Number(req.body.female) || 0;
    const total = male + female;

    const updated = await Training.findOneAndUpdate(
      {
        _id: req.params.id,
        organizationId: req.user.organizationId,
      },
      {
        title: req.body.title,
        category: req.body.category || "",
        dateRange: req.body.dateRange || "",
        male,
        female,
        total,
        status: req.body.status || "Completed",
        participants,
      },
      {
        new: true,
        runValidators: true,
      }
    ).populate("participants");

    res.json(updated);
  } catch (err) {
    res.status(500).json({
      message: "Error updating training",
      error: err.message,
    });
  }
});
// Get trainings
app.get("/trainings", auth, async (req, res) => {
  try {
    const trainings = await Training.find({
      organizationId: req.user.organizationId,
    })
      .populate("participants")
      .sort({ createdAt: -1 });

    res.json(trainings);
  } catch (err) {
    res.status(500).json({
      message: "Error fetching trainings",
      error: err.message,
    });
  }
});

// Delete training
app.delete("/trainings/:id", auth, async (req, res) => {
  try {
    await Training.findOneAndDelete({
      _id: req.params.id,
      organizationId: req.user.organizationId,
    });

    res.json({ message: "Training deleted successfully" });
  } catch (err) {
    res.status(500).json({
      message: "Error deleting training",
      error: err.message,
    });
  }
});

/* ------------------ STATS ------------------ */

// Dashboard stats
app.get("/stats", auth, async (req, res) => {
  try {
    const total = await Beneficiary.countDocuments({
      organizationId: req.user.organizationId,
    });

    const programs = await Beneficiary.distinct("program", {
      organizationId: req.user.organizationId,
    });

    res.json({
      totalBeneficiaries: total,
      totalPrograms: programs.length,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Program stats
app.get("/program-stats", auth, async (req, res) => {
  try {
    const stats = await Beneficiary.aggregate([
      {
        $match: {
          organizationId: new mongoose.Types.ObjectId(
            String(req.user.organizationId)
          ),
        },
      },
      {
        $group: {
          _id: "$program",
          count: { $sum: 1 },
        },
      },
    ]);

    res.json(stats);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/* ------------------ FRONTEND ------------------ */

// Serve index.html
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

/* ------------------ START SERVER ------------------ */

app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server is flying on port ${PORT}`);
});