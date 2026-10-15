const mongoose = require("mongoose");
const Lookup = require("../models/Lookup");

// Replace with your MongoDB connection string
const MONGO_URI =
    process.env.MONGO_URI ||
    "mongodb://127.0.0.1:27017/your_database_name";

const lookups = [

    // ===============================
    // Vulnerable Groups
    // ===============================

    {
        type: "VulnerableGroup",
        name: "Elderly",
        value: "Elderly",
        code: "ELDERLY",
        active: true
    },

    {
        type: "VulnerableGroup",
        name: "Orphan",
        value: "Orphan",
        code: "ORPHAN",
        active: true
    },

    {
        type: "VulnerableGroup",
        name: "Female Headed Household",
        value: "Female Headed Household",
        code: "FHH",
        active: true
    },

    {
        type: "VulnerableGroup",
        name: "Child At Risk",
        value: "Child At Risk",
        code: "CAR",
        active: true
    },

    {
        type: "VulnerableGroup",
        name: "Refugee",
        value: "Refugee",
        code: "REFUGEE",
        active: true
    },

    {
        type: "VulnerableGroup",
        name: "Internally Displaced Person",
        value: "Internally Displaced Person",
        code: "IDP",
        active: true
    },

    {
        type: "VulnerableGroup",
        name: "Extreme Poor Household",
        value: "Extreme Poor Household",
        code: "EPH",
        active: true
    }

];

async function seedLookups() {

    try {

        await mongoose.connect(MONGO_URI);

        console.log("MongoDB Connected");

        for (const item of lookups) {

            await Lookup.updateOne(

                {
                    type: item.type,
                    code: item.code
                },

                {
                    $set: item
                },

                {
                    upsert: true
                }

            );

        }

        console.log("Lookup seed completed.");

        process.exit(0);

    } catch (error) {

        console.error(error);

        process.exit(1);

    }

}

seedLookups();