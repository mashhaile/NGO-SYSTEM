const {
    getErrorStatus,
    getErrorMessage
} = require("../utils/errorStatus");

const {
    createDonation,
    getDonations,
    getDonationById,
    updateDonation,
    deleteDonation

} = require("../services/donationService");


const subscriptionService =
    require("../services/subscriptionService");

const donationFunding =
    require("../services/donationFunding");


const {
    logAudit

} = require("../services/auditHelper");


const Donation =
    require("../models/donation");



// ==========================================
// CREATE DONATION
// ==========================================

const createDonationController = async (

    req,
    res

) => {

    try {

        const organizationId =
            req.user.organizationId;


        // ==========================================
        // CHECK SUBSCRIPTION LIMIT
        // ==========================================

        await subscriptionService.checkResourceLimit(

            organizationId,

            "donations"

        );


        // ==========================================
        // CREATE DONATION
        // ==========================================

        const donation =
            await createDonation(

                req.body,

                organizationId,

                req.user.userId

            );


        // ==========================================
        // GET POPULATED DONATION
        // ==========================================

        const populatedDonation =
            await getDonationById(

                donation._id,

                organizationId

            );


        // ==========================================
        // AUDIT
        // ==========================================

        await logAudit({

            req,

            action:
                "create",

            module:
                "donation",

            entityType:
                "Donation",

            entityId:
                donation._id,

            description:
                `Donation "${donation.title}" created`

        });


        // ==========================================
        // RESPONSE
        // ==========================================

        res.status(201).json({

            success: true,

            message:
                "Donation created successfully",

            data:
                populatedDonation

        });

    }

    catch (error) {

        console.error(

            "CREATE DONATION ERROR:",

            error

        );


        const statusCode =
            error.statusCode || 400;


        res.status(statusCode).json({

            success: false,

            message:
                error.message

        });

    }

};



// ==========================================
// GET ALL DONATIONS
// ==========================================

const getDonationsController = async (

    req,
    res

) => {

    try {

        const donations =
            await getDonations(

                req.user.organizationId,

                req.query

            );


        res.json({

            success: true,

            message:
                "Donations fetched successfully",

            data:
                donations

        });

    }

    catch (error) {

        console.error(

            "GET DONATIONS ERROR:",

            error

        );


        res.status(getErrorStatus(error)).json({

            success: false,

            message:
                getErrorMessage(error)

        });

    }

};



// ==========================================
// GET SINGLE DONATION
// ==========================================

const getDonationByIdController = async (

    req,
    res

) => {

    try {

        const donation =
            await getDonationById(

                req.params.id,

                req.user.organizationId

            );


        if (!donation) {

            return res.status(404).json({

                success: false,

                message:
                    "Donation not found"

            });

        }


        // What the donation has used and has left (deliveries
        // + submitted / approved expenses, in its currency)
        const use =
            await donationFunding.donationUse(
                donation._id,
                req.user.organizationId
            );

        const plain =
            typeof donation.toObject === "function"
                ? donation.toObject()
                : donation;

        res.json({

            success: true,

            data: {
                ...plain,
                funding: {
                    currency: use.currency,
                    amount: use.amount,
                    byDeliveries: use.byDeliveries,
                    byExpenses: use.byExpenses,
                    used: use.used,
                    left: use.left
                }
            }

        });

    }

    catch (error) {

        console.error(

            "GET DONATION ERROR:",

            error

        );


        res.status(getErrorStatus(error)).json({

            success: false,

            message:
                getErrorMessage(error)

        });

    }

};



// ==========================================
// UPDATE DONATION
// ==========================================

const updateDonationController = async (

    req,
    res

) => {

    try {

        const organizationId =
            req.user.organizationId;


        const donation =
            await updateDonation(

                req.params.id,

                req.body,

                organizationId,

                req.user.userId

            );


        const updatedDonation =
            await getDonationById(

                donation._id,

                organizationId

            );


        await logAudit({

            req,

            action:
                "update",

            module:
                "donation",

            entityType:
                "Donation",

            entityId:
                donation._id,

            description:
                `Donation "${donation.title}" updated`

        });


        res.json({

            success: true,

            message:
                "Donation updated successfully",

            data:
                updatedDonation

        });

    }

    catch (error) {

        console.error(

            "UPDATE DONATION ERROR:",

            error

        );


        res.status(getErrorStatus(error)).json({

            success: false,

            message:
                getErrorMessage(error)

        });

    }

};



// ==========================================
// DELETE DONATION
// ==========================================

const deleteDonationController = async (

    req,
    res

) => {

    try {

        const organizationId =
            req.user.organizationId;


        const donation =
            await Donation.findOne({

                _id:
                    req.params.id,

                organization:
                    organizationId,

                isDeleted:
                    false

            });


        if (!donation) {

            return res.status(404).json({

                success: false,

                message:
                    "Donation not found"

            });

        }


        await deleteDonation(

            req.params.id,

            organizationId,

            req.user.userId

        );


        await logAudit({

            req,

            action:
                "delete",

            module:
                "donation",

            entityType:
                "Donation",

            entityId:
                donation._id,

            severity:
                "warning",

            description:
                `Donation "${donation.title}" deleted`

        });


        res.json({

            success: true,

            message:
                "Donation deleted successfully"

        });

    }

    catch (error) {

        console.error(

            "DELETE DONATION ERROR:",

            error

        );


        res.status(getErrorStatus(error)).json({

            success: false,

            message:
                getErrorMessage(error)

        });

    }

};



// ==========================================
// EXPORTS
// ==========================================

module.exports = {

    createDonationController,

    getDonationsController,

    getDonationByIdController,

    updateDonationController,

    deleteDonationController

};