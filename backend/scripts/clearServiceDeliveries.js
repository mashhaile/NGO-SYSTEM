require("dotenv").config();

const mongoose = require("mongoose");

const ServiceDelivery =
    require("../models/ServiceDelivery");

const ServiceDeliveryBeneficiary =
    require("../models/ServiceDeliveryBeneficiary");


// ======================================================
// DATABASE CONNECTION
// ======================================================

const connectDB = async () => {

    try {

        if (
            !process.env.MONGO_URI
        ) {

            throw new Error(
                "MONGO_URI is not defined in the environment."
            );

        }


        const connection =
            await mongoose.connect(
                process.env.MONGO_URI
            );


        console.log(
            `MongoDB connected: ${connection.connection.host}`
        );

    }

    catch (
        error
    ) {

        console.error(
            "MongoDB connection failed:"
        );

        console.error(
            error.message
        );

        process.exit(1);

    }

};


// ======================================================
// CLEAN SERVICE DELIVERIES
// ======================================================

const clearServiceDeliveries = async () => {

    try {

        await connectDB();


        // ==================================================
        // FIND ALL SERVICE DELIVERIES
        // ==================================================

        const serviceDeliveries =
            await ServiceDelivery.find(
                {}
            )
            .select(
                "_id deliveryNumber organization"
            )
            .lean();


        console.log(
            `Found ${serviceDeliveries.length} Service Delivery record(s).`
        );


        if (
            serviceDeliveries.length === 0
        ) {

            console.log(
                "No Service Delivery records found."
            );

            return;

        }


        const serviceDeliveryIds =
            serviceDeliveries.map(
                (
                    serviceDelivery
                ) =>
                    serviceDelivery._id
            );


        // ==================================================
        // SHOW RECORDS THAT WILL BE DELETED
        // ==================================================

        console.log(
            "Service Deliveries to be removed:"
        );


        serviceDeliveries.forEach(
            (
                serviceDelivery
            ) => {

                console.log(
                    `- ${serviceDelivery.deliveryNumber || serviceDelivery._id}`
                );

            }
        );


        // ==================================================
        // DELETE BENEFICIARY ASSOCIATIONS
        // ==================================================

        const beneficiaryResult =
            await ServiceDeliveryBeneficiary.deleteMany({

                serviceDelivery: {
                    $in:
                        serviceDeliveryIds
                }

            });


        console.log(
            `Deleted ${beneficiaryResult.deletedCount} Service Delivery Beneficiary record(s).`
        );


        // ==================================================
        // DELETE SERVICE DELIVERIES
        // ==================================================

        const serviceResult =
            await ServiceDelivery.deleteMany({

                _id: {
                    $in:
                        serviceDeliveryIds
                }

            });


        console.log(
            `Deleted ${serviceResult.deletedCount} Service Delivery record(s).`
        );


        // ==================================================
        // VERIFY SERVICE DELIVERIES
        // ==================================================

        const remainingServiceDeliveries =
            await ServiceDelivery.countDocuments(
                {}
            );


        // ==================================================
        // VERIFY BENEFICIARY ASSOCIATIONS
        // ==================================================

        const remainingBeneficiaryAssociations =
            await ServiceDeliveryBeneficiary.countDocuments(
                {}
            );


        console.log(
            "=================================================="
        );


        console.log(
            `Remaining Service Delivery records: ${remainingServiceDeliveries}`
        );


        console.log(
            `Remaining Service Delivery Beneficiary records: ${remainingBeneficiaryAssociations}`
        );


        console.log(
            "=================================================="
        );


        if (
            remainingServiceDeliveries === 0 &&
            remainingBeneficiaryAssociations === 0
        ) {

            console.log(
                "Service Delivery cleanup completed successfully."
            );

        }

        else {

            console.warn(
                "Cleanup completed, but some records remain."
            );

        }

    }

    catch (
        error
    ) {

        console.error(
            "Service Delivery cleanup failed:"
        );

        console.error(
            error
        );

        process.exitCode = 1;

    }

    finally {

        await mongoose.disconnect();

        console.log(
            "MongoDB connection closed."
        );

    }

};


// ======================================================
// RUN
// ======================================================

clearServiceDeliveries();