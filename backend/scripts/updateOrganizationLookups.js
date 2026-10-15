const mongoose = require("mongoose");

const Organization = require("../models/Organization");

const {
    initializeOrganization
} = require("../initializers/organizationInitializer");

const connectDB = require("../config/database");



const updateOrganizationLookups = async()=>{


    try{


        await connectDB();



        const organizations = await Organization.find({
            isDeleted:false
        });



        console.log(
            `Found ${organizations.length} organizations`
        );



        for(const organization of organizations){


            console.log(
                "Updating:",
                organization.name
            );



            await initializeOrganization(

                organization._id,

                null

            );


            console.log(
                "Completed:",
                organization.name
            );


        }



        console.log(
            "All organization lookups updated successfully."
        );


        process.exit(0);



    }
    catch(error){


        console.error(
            error
        );


        process.exit(1);


    }


};



updateOrganizationLookups();