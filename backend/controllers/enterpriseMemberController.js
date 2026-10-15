const {
    logActivity
} = require("../utils/auditLogger");


const {
    createEnterpriseMember,
    getEnterpriseMembers,
    getEnterpriseMemberById,
    updateEnterpriseMember,
    deleteEnterpriseMember,
    getMembersByEnterprise,
    getEnterprisesByMember
} =
    require("../services/enterpriseMemberService");


// =====================================================
// CREATE ENTERPRISE MEMBER
// =====================================================

const createEnterpriseMemberController = async (
    req,
    res
) => {

    try {

        const member =
            await createEnterpriseMember(

                req.body,

                req.user.organizationId,

                req.user.userId

            );


        await logActivity({

            req,

            action:
                "CREATE",

            module:
                "EnterpriseMember",

            entityType:
                "EnterpriseMember",

            entityId:
                member._id,

            description:
                "Beneficiary added to enterprise"

        });


        return res.status(201).json({

            success:
                true,

            message:
                "Enterprise member created successfully",

            data:
                member

        });

    }

    catch (error) {

        console.error(
            "CREATE ENTERPRISE MEMBER ERROR:",
            error
        );


        return res.status(

            error.statusCode || 400

        ).json({

            success:
                false,

            message:
                error.message

        });

    }

};


// =====================================================
// GET ALL ENTERPRISE MEMBERS
// =====================================================

const getEnterpriseMembersController = async (
    req,
    res
) => {

    try {

        const members =
            await getEnterpriseMembers(

                req.user.organizationId,

                req.query

            );


        return res.json({

            success:
                true,

            message:
                "Enterprise members fetched successfully",

            data:
                members

        });

    }

    catch (error) {

        console.error(
            "GET ENTERPRISE MEMBERS ERROR:",
            error
        );


        return res.status(

            error.statusCode || 400

        ).json({

            success:
                false,

            message:
                error.message

        });

    }

};


// =====================================================
// GET MEMBER BY ID
// =====================================================

const getEnterpriseMemberByIdController = async (
    req,
    res
) => {

    try {

        const member =
            await getEnterpriseMemberById(

                req.params.id,

                req.user.organizationId

            );


        return res.json({

            success:
                true,

            message:
                "Enterprise member fetched successfully",

            data:
                member

        });

    }

    catch (error) {

        console.error(
            "GET ENTERPRISE MEMBER ERROR:",
            error
        );


        return res.status(

            error.statusCode || 404

        ).json({

            success:
                false,

            message:
                error.message

        });

    }

};


// =====================================================
// UPDATE ENTERPRISE MEMBER
// =====================================================

const updateEnterpriseMemberController = async (
    req,
    res
) => {

    try {

        const member =
            await updateEnterpriseMember(

                req.params.id,

                req.body,

                req.user.organizationId,

                req.user.userId

            );


        await logActivity({

            req,

            action:
                "UPDATE",

            module:
                "EnterpriseMember",

            entityType:
                "EnterpriseMember",

            entityId:
                member._id,

            description:
                "Enterprise member updated"

        });


        return res.json({

            success:
                true,

            message:
                "Enterprise member updated successfully",

            data:
                member

        });

    }

    catch (error) {

        console.error(
            "UPDATE ENTERPRISE MEMBER ERROR:",
            error
        );


        return res.status(

            error.statusCode || 400

        ).json({

            success:
                false,

            message:
                error.message

        });

    }

};


// =====================================================
// DELETE ENTERPRISE MEMBER
// =====================================================

const deleteEnterpriseMemberController = async (
    req,
    res
) => {

    try {

        const member =
            await deleteEnterpriseMember(

                req.params.id,

                req.user.organizationId,

                req.user.userId

            );


        await logActivity({

            req,

            action:
                "DELETE",

            module:
                "EnterpriseMember",

            entityType:
                "EnterpriseMember",

            entityId:
                member._id,

            description:
                "Enterprise member removed",

            severity:
                "warning"

        });


        return res.json({

            success:
                true,

            message:
                "Enterprise member removed successfully"

        });

    }

    catch (error) {

        console.error(
            "DELETE ENTERPRISE MEMBER ERROR:",
            error
        );


        return res.status(

            error.statusCode || 400

        ).json({

            success:
                false,

            message:
                error.message

        });

    }

};


// =====================================================
// GET MEMBERS BY ENTERPRISE
// =====================================================

const getMembersByEnterpriseController = async (
    req,
    res
) => {

    try {

        const members =
            await getMembersByEnterprise(

                req.params.enterpriseId,

                req.user.organizationId

            );


        return res.json({

            success:
                true,

            message:
                "Enterprise members fetched successfully",

            data:
                members

        });

    }

    catch (error) {

        console.error(
            "GET MEMBERS BY ENTERPRISE ERROR:",
            error
        );


        return res.status(

            error.statusCode || 400

        ).json({

            success:
                false,

            message:
                error.message

        });

    }

};


// =====================================================
// GET ENTERPRISES BY BENEFICIARY
// =====================================================

const getEnterprisesByMemberController = async (
    req,
    res
) => {

    try {

        const enterprises =
            await getEnterprisesByMember(

                req.params.beneficiaryId,

                req.user.organizationId

            );


        return res.json({

            success:
                true,

            message:
                "Beneficiary enterprises fetched successfully",

            data:
                enterprises

        });

    }

    catch (error) {

        console.error(
            "GET ENTERPRISES BY BENEFICIARY ERROR:",
            error
        );


        return res.status(

            error.statusCode || 400

        ).json({

            success:
                false,

            message:
                error.message

        });

    }

};


// =====================================================
// EXPORT
// =====================================================

module.exports = {

    createEnterpriseMemberController,

    getEnterpriseMembersController,

    getEnterpriseMemberByIdController,

    updateEnterpriseMemberController,

    deleteEnterpriseMemberController,

    getMembersByEnterpriseController,

    getEnterprisesByMemberController

};