const mongoose = require("mongoose");
const dotenv = require("dotenv");
const bcrypt = require("bcrypt");

const User = require("../models/user");

const {
    ROLES,
    USER_STATUS
} = require("../config/constants");

dotenv.config();


async function seedSuperAdmin() {

    try {

        await mongoose.connect(
            process.env.MONGO_URI
        );

        console.log("MongoDB Connected");


        const email =
            "superadmin@ngo.org";


        const existing =
            await User.findOne({
                email
            });


        if (existing) {

            console.log(
                "⚠️ Super Admin already exists."
            );

            return;

        }


        const hashedPassword =
            await bcrypt.hash(
                "SuperAdmin123!",
                10
            );


        const superAdmin =
            await User.create({

                organization: null,

                name:
                    "System Administrator",

                email,

                password:
                    hashedPassword,

                role:
                    ROLES.SUPER_ADMIN,

                status:
                    USER_STATUS.ACTIVE

            });


        console.log(
            "✅ Super Admin created successfully."
        );

        console.log({

            id:
                superAdmin._id,

            name:
                superAdmin.name,

            email:
                superAdmin.email,

            role:
                superAdmin.role

        });

    }
    catch (error) {

        console.error(
            "❌ Error seeding Super Admin"
        );

        console.error(error);

    }
    finally {

        await mongoose.connection.close();

        process.exit();

    }

}


seedSuperAdmin();