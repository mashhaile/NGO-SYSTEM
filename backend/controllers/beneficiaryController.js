const {
    logActivity
} = require("../utils/auditLogger");


const {
    createBeneficiary,
    getBeneficiaries,
    getBeneficiaryById,
    updateBeneficiary,
    deleteBeneficiary,
    getBeneficiaryLookup
} = require("../services/beneficiaryService");


const Beneficiary =
    require("../models/Beneficiary");


// =====================================================
// HELPERS
// =====================================================

const getUserId = (req) => {

    return (
        req.user?.userId ||
        req.user?._id ||
        null
    );

};


const getOrganizationId = (req) => {

    return (
        req.organizationId ||
        req.user?.organizationId ||
        null
    );

};


// =====================================================
// CREATE BENEFICIARY
// =====================================================

const createBeneficiaryController = async (
    req,
    res
) => {

    try {

        const organizationId =
            getOrganizationId(req);

        const userId =
            getUserId(req);


        if (!organizationId) {

            return res.status(400).json({

                success: false,

                message:
                    "Organization context is required."

            });

        }


        if (!userId) {

            return res.status(401).json({

                success: false,

                message:
                    "Authenticated user is required."

            });

        }


        const beneficiary =
            await createBeneficiary(

                req.body,

                organizationId,

                userId

            );


        await logActivity({

            req,

            action: "CREATE",

            module: "Beneficiary",

            entityType: "Beneficiary",

            entityId:
                beneficiary._id,

            description:
                `Beneficiary "${beneficiary.firstName} ${beneficiary.lastName}" created`

        });


        return res.status(201).json({

            success: true,

            message:
                "Beneficiary created successfully",

            data:
                beneficiary

        });

    }

    catch (error) {

        console.error(
            "CREATE BENEFICIARY ERROR:",
            error
        );


        return res.status(
            error.statusCode || 400
        ).json({

            success: false,

            message:
                error.message

        });

    }

};


// =====================================================
// GET ALL BENEFICIARIES
// =====================================================

const getBeneficiariesController = async (
    req,
    res
) => {

    try {

        const organizationId =
            getOrganizationId(req);


        if (!organizationId) {

            return res.status(400).json({

                success: false,

                message:
                    "Organization context is required."

            });

        }


        const beneficiaries =
            await getBeneficiaries(

                organizationId,

                req.query

            );


        return res.json({

            success: true,

            message:
                "Beneficiaries fetched successfully",

            data:
                beneficiaries

        });

    }

    catch (error) {

        console.error(
            "GET BENEFICIARIES ERROR:",
            error
        );


        return res.status(
            error.statusCode || 500
        ).json({

            success: false,

            message:
                error.message

        });

    }

};


// =====================================================
// GET BENEFICIARY BY ID
// =====================================================

const getBeneficiaryByIdController = async (
    req,
    res
) => {

    try {

        const organizationId =
            getOrganizationId(req);


        if (!organizationId) {

            return res.status(400).json({

                success: false,

                message:
                    "Organization context is required."

            });

        }


        const beneficiary =
            await getBeneficiaryById(

                req.params.id,

                organizationId

            );


        return res.json({

            success: true,

            data:
                beneficiary

        });

    }

    catch (error) {

        console.error(
            "GET BENEFICIARY ERROR:",
            error
        );


        return res.status(
            error.statusCode || 404
        ).json({

            success: false,

            message:
                error.message

        });

    }

};


// =====================================================
// UPDATE BENEFICIARY
// =====================================================

const updateBeneficiaryController = async (
    req,
    res
) => {

    try {

        const organizationId =
            getOrganizationId(req);

        const userId =
            getUserId(req);


        if (!organizationId) {

            return res.status(400).json({

                success: false,

                message:
                    "Organization context is required."

            });

        }


        if (!userId) {

            return res.status(401).json({

                success: false,

                message:
                    "Authenticated user is required."

            });

        }


        const updated =
            await updateBeneficiary(

                req.params.id,

                req.body,

                organizationId,

                userId

            );


        await logActivity({

            req,

            action: "UPDATE",

            module: "Beneficiary",

            entityType: "Beneficiary",

            entityId:
                updated._id,

            description:
                `Beneficiary "${updated.firstName} ${updated.lastName}" updated`

        });


        return res.json({

            success: true,

            message:
                "Beneficiary updated successfully",

            data:
                updated

        });

    }

    catch (error) {

        console.error(
            "UPDATE BENEFICIARY ERROR:",
            error
        );


        return res.status(
            error.statusCode || 400
        ).json({

            success: false,

            message:
                error.message

        });

    }

};


// =====================================================
// DELETE BENEFICIARY
// =====================================================

const deleteBeneficiaryController = async (
    req,
    res
) => {

    try {

        const organizationId =
            getOrganizationId(req);

        const userId =
            getUserId(req);


        if (!organizationId) {

            return res.status(400).json({

                success: false,

                message:
                    "Organization context is required."

            });

        }


        if (!userId) {

            return res.status(401).json({

                success: false,

                message:
                    "Authenticated user is required."

            });

        }


        const beneficiary =
            await Beneficiary.findOne({

                _id:
                    req.params.id,

                organization:
                    organizationId,

                isDeleted:
                    false

            });


        if (!beneficiary) {

            return res.status(404).json({

                success: false,

                message:
                    "Beneficiary not found"

            });

        }


        await deleteBeneficiary(

            req.params.id,

            organizationId,

            userId

        );


        await logActivity({

            req,

            action: "DELETE",

            module: "Beneficiary",

            entityType: "Beneficiary",

            entityId:
                beneficiary._id,

            description:
                `Beneficiary "${beneficiary.firstName} ${beneficiary.lastName}" deleted`,

            severity:
                "warning"

        });


        return res.json({

            success: true,

            message:
                "Beneficiary deleted successfully"

        });

    }

    catch (error) {

        console.error(
            "DELETE BENEFICIARY ERROR:",
            error
        );


        return res.status(
            error.statusCode || 400
        ).json({

            success: false,

            message:
                error.message

        });

    }

};


// =====================================================
// BENEFICIARY LOOKUP
// =====================================================

const getBeneficiaryLookupController = async (
    req,
    res
) => {

    try {

        const organizationId =
            getOrganizationId(req);


        if (!organizationId) {

            return res.status(400).json({

                success: false,

                message:
                    "Organization context is required."

            });

        }


        const beneficiaries =
            await getBeneficiaryLookup(

                organizationId,

                req.query.program

            );


        const data =
            beneficiaries.map(

                item => ({

                    _id:
                        item._id,

                    beneficiaryNumber:
                        item.beneficiaryNumber,

                    firstName:
                        item.firstName || "",

                    middleName:
                        item.middleName || "",

                    lastName:
                        item.lastName || "",

                    fullName:
                        `${item.firstName || ""} ${item.lastName || ""}`.trim()

                })

            );


        return res.json({

            success: true,

            data

        });

    }

    catch (error) {

        console.error(
            "BENEFICIARY LOOKUP ERROR:",
            error
        );


        return res.status(
            error.statusCode || 500
        ).json({

            success: false,

            message:
                error.message

        });

    }

};


// =====================================================
// EXPORTS
// =====================================================

module.exports = {

    createBeneficiaryController,

    getBeneficiariesController,

    getBeneficiaryByIdController,

    updateBeneficiaryController,

    deleteBeneficiaryController,

    getBeneficiaryLookupController

};
