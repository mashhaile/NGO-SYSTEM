require("dotenv").config();
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

mongoose.connect(process.env.MONGO_URI || "mongodb://127.0.0.1:27017/ngo_test")
  .then(() => console.log("Connected"))
  .catch(err => console.log(err));

const UserSchema = new mongoose.Schema({
  email: String,
  password: String,
});

const User = mongoose.model("User", UserSchema);

async function run() {
  const hashed = await bcrypt.hash("123", 10);

  await User.deleteMany({ email: "admin@test.com" });

  await User.create({
    email: "admin@test.com",
    password: hashed,
  });

  console.log("Admin created: admin@test.com / 123");
  process.exit();
}

run();