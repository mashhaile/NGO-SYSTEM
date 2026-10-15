require("dotenv").config();

const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const User = require("../models/user");

const connectDB = require("../config/db");

const {
    ROLES,
    USER_STATUS
} = require("../config/constants");


const createSuperAdmin = async()=>{

    try{

        await connectDB();


        const exists =
            await User.findOne({

                role:ROLES.SUPER_ADMIN

            });


        if(exists){

            console.log(
                "Super Admin already exists"
            );

            process.exit();

        }



        const password =
            await bcrypt.hash(
                "123456",
                10
            );



        const admin =
            await User.create({

                name:"System Administrator",

                email:"admin@test.com",

                password,

                role:
                ROLES.SUPER_ADMIN,

                status:
                USER_STATUS.ACTIVE

            });



        console.log(
            "Super Admin created:",
            admin.email
        );


        process.exit();


    }

    catch(error){

        console.log(error);

        process.exit(1);

    }

};


createSuperAdmin();