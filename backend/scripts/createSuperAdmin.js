// =====================================================
// CREATE SUPER ADMIN
// =====================================================
//
// Usage (from backend/):
//
//     node scripts/createSuperAdmin.js
//         -> local/dev default: admin@test.com / 123456
//
//     node scripts/createSuperAdmin.js you@example.org "Your Name"
//         -> uses that email; generates a strong password and
//            prints it ONCE (change it after first login)
//
//     node scripts/createSuperAdmin.js you@example.org "Your Name" "Password"
//         -> uses the given password (min. 12 characters)
//
// With NODE_ENV=production an email is required and the weak
// test password is never used.
//
// =====================================================

require("dotenv").config();

const crypto = require("crypto");
const bcrypt = require("bcrypt");

const User = require("../models/user");
const connectDB = require("../config/db");

const {
    ROLES,
    USER_STATUS
} = require("../config/constants");


const isProduction =
    process.env.NODE_ENV === "production";


const generatePassword = () =>
    crypto
        .randomBytes(12)
        .toString("base64url");


const createSuperAdmin = async () => {

    const [emailArg, nameArg, passwordArg] =
        process.argv.slice(2);

    if (isProduction && !emailArg) {
        console.error(
            "In production pass an email: node scripts/createSuperAdmin.js you@example.org \"Your Name\""
        );
        process.exit(1);
    }

    if (passwordArg && passwordArg.length < 12) {
        console.error("The password must be at least 12 characters.");
        process.exit(1);
    }

    const email =
        (emailArg || "admin@test.com").trim().toLowerCase();

    const name =
        nameArg || "System Administrator";

    const plainPassword =
        passwordArg ||
        (emailArg ? generatePassword() : "123456");

    try {

        await connectDB();

        const exists =
            await User.findOne({
                role: ROLES.SUPER_ADMIN
            });

        if (exists) {
            console.log(
                `Super Admin already exists (${exists.email}). Nothing changed.`
            );
            process.exit();
        }

        const admin =
            await User.create({
                name,
                email,
                password: await bcrypt.hash(plainPassword, 10),
                role: ROLES.SUPER_ADMIN,
                status: USER_STATUS.ACTIVE
            });

        console.log("Super Admin created:", admin.email);

        if (!passwordArg) {
            console.log("Password (shown once, change it after first login):", plainPassword);
        }

        process.exit();

    }
    catch (error) {

        console.log(error);

        process.exit(1);

    }

};


createSuperAdmin();
