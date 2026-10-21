const {
    getErrorStatus,
    getErrorMessage
} = require("../utils/errorStatus");

const {

    createDonor,

    getDonors,

    getDonorById,

    updateDonor,

    deleteDonor,

    getDonorLookup

} = require("../services/donorService");



const subscriptionService =
    require("../services/subscriptionService");



const {

    logAudit

} = require("../services/auditHelper");



// ==========================================
// CREATE
// ==========================================

const createDonorController = async (
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

            "donors"

        );


        // ==========================================
        // CREATE DONOR
        // ==========================================

        const donor =
            await createDonor(

                req.body,

                organizationId,

                req.user.userId

            );


        // ==========================================
        // AUDIT
        // ==========================================

        await logAudit({

            req,

            action:
                "create",

            module:
                "donor",

            entityType:
                "Donor",

            entityId:
                donor._id,

            description:
                `Donor "${donor.name}" created`

        });


        // ==========================================
        // RESPONSE
        // ==========================================

        res.status(201).json({

            success: true,

            message:
                "Donor created successfully",

            data:
                donor

        });

    }

    catch (error) {

        console.error(

            "CREATE DONOR ERROR:",

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
// GET ALL
// ==========================================

const getDonorsController = async (
    req,
    res
) => {

    try {

        const result =
            await getDonors(

                req.user.organizationId,

                req.query

            );


        res.json({

            success: true,

            data:
                result.data,

            pagination:
                result.pagination

        });

    }

    catch (error) {

        console.error(

            "GET DONORS ERROR:",

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
// LOOKUP
// ==========================================

const getDonorLookupController = async (
    req,
    res
) => {

    try {

        const donors =
            await getDonorLookup(
                req.user.organizationId
            );


        res.json({

            success: true,

            data:
                donors

        });

    }

    catch (error) {

        console.error(

            "GET DONOR LOOKUP ERROR:",

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
// GET ONE
// ==========================================

const getDonorByIdController = async (
    req,
    res
) => {

    try {

        const donor =
            await getDonorById(

                req.params.id,

                req.user.organizationId

            );


        if (!donor) {

            return res.status(404).json({

                success: false,

                message:
                    "Donor not found"

            });

        }


        res.json({

            success: true,

            data:
                donor

        });

    }

    catch (error) {

        console.error(

            "GET DONOR ERROR:",

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
// UPDATE
// ==========================================

const updateDonorController = async (
    req,
    res
) => {

    try {

        const donor =
            await updateDonor(

                req.params.id,

                req.body,

                req.user.organizationId,

                req.user.userId

            );


        await logAudit({

            req,

            action:
                "update",

            module:
                "donor",

            entityType:
                "Donor",

            entityId:
                donor._id,

            description:
                `Donor "${donor.name}" updated`

        });


        res.json({

            success: true,

            message:
                "Donor updated successfully",

            data:
                donor

        });

    }

    catch (error) {

        console.error(

            "UPDATE DONOR ERROR:",

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
// DELETE
// ==========================================

const deleteDonorController = async (
    req,
    res
) => {

    try {

        const donor =
            await deleteDonor(

                req.params.id,

                req.user.organizationId,

                req.user.userId

            );


        await logAudit({

            req,

            action:
                "delete",

            module:
                "donor",

            entityType:
                "Donor",

            entityId:
                donor._id,

            description:
                `Donor "${donor.name}" deleted`,

            severity:
                "warning"

        });


        res.json({

            success: true,

            message:
                "Donor deleted successfully"

        });

    }

    catch (error) {

        console.error(

            "DELETE DONOR ERROR:",

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

    createDonorController,

    getDonorsController,

    getDonorLookupController,

    getDonorByIdController,

    updateDonorController,

    deleteDonorController

};