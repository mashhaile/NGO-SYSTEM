const {
    getErrorStatus,
    getErrorMessage
} = require("../utils/errorStatus");

const {
    logActivity
} = require("../utils/auditLogger");


const {
    createEnterprise,
    getEnterprises,
    getEnterpriseById,
    updateEnterprise,
    deleteEnterprise,
    getEnterpriseLookup,
    getEnterprisesByBeneficiary
} = require("../services/enterpriseService");


// =====================================================
// CREATE ENTERPRISE
// =====================================================

const createEnterpriseController = async (
    req,
    res
) => {

    try {

        const enterprise =
            await createEnterprise(

                req.body,

                req.user.organizationId,

                req.user.userId

            );


        await logActivity({

            req,

            action: "CREATE",

            module: "Enterprise",

            entityType: "Enterprise",

            entityId:
                enterprise._id,

            description:
                `Enterprise "${enterprise.name}" created`

        });


        res.status(201).json({

            success: true,

            message:
                "Enterprise created successfully",

            data:
                enterprise

        });

    }

    catch (error) {

        console.error(
            "CREATE ENTERPRISE ERROR:",
            error
        );


        res.status(
            error.statusCode || 400
        ).json({

            success: false,

            message:
                error.message

        });

    }

};


// =====================================================
// GET ALL ENTERPRISES
// =====================================================

const getEnterprisesController = async (
    req,
    res
) => {

    try {

        const enterprises =
            await getEnterprises(

                req.user.organizationId,

                req.query

            );


        res.json({

            success: true,

            message:
                "Enterprises fetched successfully",

            data:
                enterprises

        });

    }

    catch (error) {

        console.error(
            "GET ENTERPRISES ERROR:",
            error
        );


        res.status(getErrorStatus(error)).json({

            success: false,

            message:
                getErrorMessage(error)

        });

    }

};


// =====================================================
// GET ENTERPRISE BY ID
// =====================================================

const getEnterpriseByIdController = async (
    req,
    res
) => {

    try {

        const enterprise =
            await getEnterpriseById(

                req.params.id,

                req.user.organizationId

            );


        res.json({

            success: true,

            data:
                enterprise

        });

    }

    catch (error) {

        console.error(
            "GET ENTERPRISE ERROR:",
            error
        );


        res.status(getErrorStatus(error)).json({

            success: false,

            message:
                getErrorMessage(error)

        });

    }

};


// =====================================================
// UPDATE ENTERPRISE
// =====================================================

const updateEnterpriseController = async (
    req,
    res
) => {

    try {

        const enterprise =
            await updateEnterprise(

                req.params.id,

                req.body,

                req.user.organizationId,

                req.user.userId

            );


        await logActivity({

            req,

            action: "UPDATE",

            module: "Enterprise",

            entityType: "Enterprise",

            entityId:
                enterprise._id,

            description:
                `Enterprise "${enterprise.name}" updated`

        });


        res.json({

            success: true,

            message:
                "Enterprise updated successfully",

            data:
                enterprise

        });

    }

    catch (error) {

        console.error(
            "UPDATE ENTERPRISE ERROR:",
            error
        );


        res.status(
            error.statusCode || 400
        ).json({

            success: false,

            message:
                error.message

        });

    }

};


// =====================================================
// DELETE ENTERPRISE
// =====================================================

const deleteEnterpriseController = async (
    req,
    res
) => {

    try {

        const enterprise =
            await deleteEnterprise(

                req.params.id,

                req.user.organizationId,

                req.user.userId

            );


        await logActivity({

            req,

            action: "DELETE",

            module: "Enterprise",

            entityType: "Enterprise",

            entityId:
                enterprise._id,

            description:
                `Enterprise "${enterprise.name}" deleted`,

            severity:
                "warning"

        });


        res.json({

            success: true,

            message:
                "Enterprise deleted successfully"

        });

    }

    catch (error) {

        console.error(
            "DELETE ENTERPRISE ERROR:",
            error
        );


        res.status(getErrorStatus(error)).json({

            success: false,

            message:
                getErrorMessage(error)

        });

    }

};


// =====================================================
// ENTERPRISE LOOKUP
// =====================================================

const getEnterpriseLookupController = async (
    req,
    res
) => {

    try {

        const enterprises =
            await getEnterpriseLookup(

                req.user.organizationId

            );


        const data =
            enterprises.map(

                item => ({

                    _id:
                        item._id,

                    enterpriseNumber:
                        item.enterpriseNumber,

                    name:
                        item.name,

                    beneficiary:
                        item.beneficiary

                })

            );


        res.json({

            success: true,

            data

        });

    }

    catch (error) {

        console.error(
            "ENTERPRISE LOOKUP ERROR:",
            error
        );


        res.status(getErrorStatus(error)).json({

            success: false,

            message:
                getErrorMessage(error)

        });

    }

};


// =====================================================
// GET ENTERPRISES BY BENEFICIARY
// =====================================================

const getEnterprisesByBeneficiaryController =
    async (
        req,
        res
    ) => {

        try {

            const enterprises =
                await getEnterprisesByBeneficiary(

                    req.params.beneficiaryId,

                    req.user.organizationId,

                    req.query

                );


            res.json({

                success: true,

                data:
                    enterprises

            });

        }

        catch (error) {

            console.error(
                "GET ENTERPRISES BY BENEFICIARY ERROR:",
                error
            );


            res.status(getErrorStatus(error)).json({

                success: false,

                message:
                    getErrorMessage(error)

            });

        }

    };


// =====================================================
// EXPORTS
// =====================================================

module.exports = {

    createEnterpriseController,

    getEnterprisesController,

    getEnterpriseByIdController,

    updateEnterpriseController,

    deleteEnterpriseController,

    getEnterpriseLookupController,

    getEnterprisesByBeneficiaryController

};