const dotenv = require("dotenv");

const env = process.env.NODE_ENV || "local";

dotenv.config({
  path: `.env.${env}`
});

module.exports = {
  NODE_ENV: env,
  MONGO_URI: process.env.MONGO_URI,
  JWT_SECRET: process.env.JWT_SECRET,
  CLOUDINARY_NAME: process.env.CLOUDINARY_NAME,
  CLOUDINARY_KEY: process.env.CLOUDINARY_KEY,
  CLOUDINARY_SECRET: process.env.CLOUDINARY_SECRET,
};