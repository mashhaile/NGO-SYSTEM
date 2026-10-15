const EnterpriseMember =
    require("../models/EnterpriseMember");

const Enterprise =
    require("../models/Enterprise");

const Beneficiary =
    require("../models/Beneficiary");

const {
    processCustomFields
} =
    require("../utils/customFieldProcessor");

const queryHelper =
    require("../utils/queryHelper");


// =====================================================
// VERIFY ENTERPRISE
// =====================================================

const verifyEnterprise = async (
    enterpriseId,
    organizationId
) => {

    if (!enterpriseId) {

        const error =
            new Error(
                "Enterprise is required"
            );

        error.statusCode = 400;

        throw error;

    }


    if (!organizationId) {

        const error =
            new Error(
                "Organization is required"
            );

        error.statusCode = 400;

        throw error;

    }


    const enterprise =
        await Enterprise.findOne({

            _id:
                enterpriseId,

            organization:
                organizationId,

            isDeleted:
                false

        });


    if (!enterprise) {

        const error =
            new Error(
                "Enterprise not found or does not belong to this organization"
            );

        error.statusCode = 404;

        throw error;

    }


    return enterprise;

};


// =====================================================
// VERIFY BENEFICIARY
// =====================================================

const verifyBeneficiary = async (
    beneficiaryId,
    organizationId
) => {

    if (!beneficiaryId) {

        const error =
            new Error(
                "Beneficiary is required"
            );

        error.statusCode = 400;

        throw error;

    }


    const beneficiary =
        await Beneficiary.findOne({

            _id:
                beneficiaryId,

            organization:
                organizationId,

            isDeleted:
                false

        });


    if (!beneficiary) {

        const error =
            new Error(
                "Beneficiary not found or does not belong to this organization"
            );

        error.statusCode = 404;

        throw error;

    }


    return beneficiary;

};


// =====================================================
// VALIDATE MEMBER ROLE
// =====================================================

const validateMemberRole = (
    memberRole
) => {

    if (
        memberRole === undefined ||
        memberRole === null ||
        memberRole === ""
    ) {

        return "Member";

    }


    const allowedRoles = [

        "Member",
        "Partner",
        "Shareholder",
        "Manager",
        "Employee"

    ];


    const value =
        String(
            memberRole
        ).trim();


    if (
        !allowedRoles.includes(value)
    ) {

        const error =
            new Error(
                "Invalid member role. Allowed values: Member, Partner, Shareholder, Manager, Employee"
            );

        error.statusCode = 400;

        throw error;

    }


    return value;

};


// =====================================================
// VALIDATE MEMBERSHIP STATUS
// =====================================================

const validateMembershipStatus = (
    status
) => {

    if (
        status === undefined ||
        status === null ||
        status === ""
    ) {

        return "Active";

    }


    if (
        ![
            "Active",
            "Inactive"
        ].includes(status)
    ) {

        const error =
            new Error(
                "Invalid membership status. Allowed values: Active, Inactive"
            );

        error.statusCode = 400;

        throw error;

    }


    return status;

};


// =====================================================
// POPULATE MEMBER
// =====================================================

const populateMember = (
    query
) => {

    return query

        .populate({

            path:
                "enterprise",

            select:
                "enterpriseNumber name description phone email"

        })

        .populate({

            path:
                "beneficiary",

            select:
                "beneficiaryNumber firstName middleName lastName phone email"

        })

        .populate({

            path:
                "customFields.fieldId",

            select:
                "label key type options required placeholder validation active module"

        });

};


// =====================================================
// CREATE ENTERPRISE MEMBER
// =====================================================

const createEnterpriseMember = async (
    data,
    organizationId,
    userId
) => {

    await verifyEnterprise(

        data.enterprise,

        organizationId

    );


    await verifyBeneficiary(

        data.beneficiary,

        organizationId

    );


    const existingMember =
        await EnterpriseMember.findOne({

            organization:
                organizationId,

            enterprise:
                data.enterprise,

            beneficiary:
                data.beneficiary,

            isDeleted:
                false

        });


    if (existingMember) {

        const error =
            new Error(
                "Beneficiary is already a member of this enterprise"
            );

        error.statusCode = 409;

        throw error;

    }


    const {

        customFields = [],

        ...memberData

    } = data;


    const memberRole =
        validateMemberRole(

            memberData.memberRole

        );


    const status =
        validateMembershipStatus(

            memberData.status

        );


    const savedCustomFields =
        await processCustomFields(

            customFields,

            organizationId,

            true,

            "EnterpriseMember"

        );


    const member =
        await EnterpriseMember.create({

            enterprise:
                memberData.enterprise,

            beneficiary:
                memberData.beneficiary,

            memberRole,

            status,

            joinedDate:
                memberData.joinedDate,

            leftDate:
                memberData.leftDate,

            organization:
                organizationId,

            customFields:
                savedCustomFields,

            createdBy:
                userId

        });


    return await populateMember(

        EnterpriseMember.findById(
            member._id
        )

    );

};


// =====================================================
// GET ALL ENTERPRISE MEMBERS
// =====================================================

const getEnterpriseMembers = async (
    organizationId,
    reqQuery = {}
) => {

    const query = {
        ...reqQuery
    };


    delete query.organization;


    // =====================================================
    // VERIFY ENTERPRISE FILTER
    // =====================================================

    if (
        query.enterprise
    ) {

        await verifyEnterprise(
            query.enterprise,
            organizationId
        );

    }


    // =====================================================
    // VERIFY BENEFICIARY FILTER
    // =====================================================

    if (
        query.beneficiary
    ) {

        await verifyBeneficiary(
            query.beneficiary,
            organizationId
        );

    }


    // =====================================================
    // VALIDATE STATUS
    // =====================================================

    if (
        query.status
    ) {

        query.status =
            validateMembershipStatus(
                query.status
            );

    }


    // =====================================================
    // VALIDATE MEMBER ROLE
    // =====================================================

    if (
        query.memberRole !== undefined &&
        query.memberRole !== null
    ) {

        query.memberRole =
            validateMemberRole(
                query.memberRole
            );

    }


    // =====================================================
    // SEARCH
    // =====================================================
    //
    // Search:
    //
    // - Member role
    // - Status
    // - Beneficiary name
    // - Beneficiary number
    // - Enterprise name
    // - Enterprise number
    //
    // =====================================================

    const search =
        typeof query.search === "string"
            ? query.search.trim()
            : "";


    if (search) {

        delete query.search;


        const searchRegex =
            new RegExp(
                search.replace(
                    /[.*+?^${}()|[\]\\]/g,
                    "\\$&"
                ),
                "i"
            );


        // =================================================
        // FIND BENEFICIARIES
        // =================================================

        const beneficiaries =
            await Beneficiary.find({

                organization:
                    organizationId,

                isDeleted:
                    false,

                $or: [

                    {
                        beneficiaryNumber:
                            searchRegex
                    },

                    {
                        firstName:
                            searchRegex
                    },

                    {
                        middleName:
                            searchRegex
                    },

                    {
                        lastName:
                            searchRegex
                    },

                    {
                        phone:
                            searchRegex
                    },

                    {
                        email:
                            searchRegex
                    }

                ]

            }).select("_id");


        // =================================================
        // FIND ENTERPRISES
        // =================================================

        const enterprises =
            await Enterprise.find({

                organization:
                    organizationId,

                isDeleted:
                    false,

                $or: [

                    {
                        enterpriseNumber:
                            searchRegex
                    },

                    {
                        name:
                            searchRegex
                    },

                    {
                        description:
                            searchRegex
                    },

                    {
                        phone:
                            searchRegex
                    },

                    {
                        email:
                            searchRegex
                    }

                ]

            }).select("_id");


        // =================================================
        // BUILD SEARCH CONDITIONS
        // =================================================

        const searchConditions = [];


        // Member role

        searchConditions.push({

            memberRole:
                searchRegex

        });


        // Status

        searchConditions.push({

            status:
                searchRegex

        });


        // Beneficiaries

        if (
            beneficiaries.length > 0
        ) {

            searchConditions.push({

                beneficiary: {

                    $in:
                        beneficiaries.map(
                            item => item._id
                        )

                }

            });

        }


        // Enterprises

        if (
            enterprises.length > 0
        ) {

            searchConditions.push({

                enterprise: {

                    $in:
                        enterprises.map(
                            item => item._id
                        )

                }

            });

        }


        query.$or =
            searchConditions;

    }


    // =====================================================
    // QUERY HELPER
    // =====================================================

    return await queryHelper({

        model:
            EnterpriseMember,

        organizationId,

        reqQuery:
            query,

        searchableFields: [],

        populate: [

            {

                path:
                    "enterprise",

                select:
                    "enterpriseNumber name description phone email"

            },

            {

                path:
                    "beneficiary",

                select:
                    "beneficiaryNumber firstName middleName lastName phone email"

            },

            {

                path:
                    "customFields.fieldId",

                select:
                    "label key type options required placeholder validation active module"

            }

        ]

    });

};


// =====================================================
// GET MEMBERS BY ENTERPRISE
// =====================================================

const getMembersByEnterprise = async (
    enterpriseId,
    organizationId
) => {

    await verifyEnterprise(

        enterpriseId,

        organizationId

    );


    const members =
        await populateMember(

            EnterpriseMember.find({

                organization:
                    organizationId,

                enterprise:
                    enterpriseId,

                isDeleted:
                    false

            })

            .sort({

                createdAt:
                    -1

            })

        );


    return members;

};


// =====================================================
// GET ENTERPRISE MEMBER BY ID
// =====================================================

const getEnterpriseMemberById = async (
    memberId,
    organizationId
) => {

    const member =
        await populateMember(

            EnterpriseMember.findOne({

                _id:
                    memberId,

                organization:
                    organizationId,

                isDeleted:
                    false

            })

        );


    if (!member) {

        const error =
            new Error(
                "Enterprise member not found"
            );

        error.statusCode = 404;

        throw error;

    }


    return member;

};


// =====================================================
// UPDATE ENTERPRISE MEMBER
// =====================================================

const updateEnterpriseMember = async (
    memberId,
    data,
    organizationId,
    userId
) => {

    const existingMember =
        await EnterpriseMember.findOne({

            _id:
                memberId,

            organization:
                organizationId,

            isDeleted:
                false

        });


    if (!existingMember) {

        const error =
            new Error(
                "Enterprise member not found"
            );

        error.statusCode = 404;

        throw error;

    }


    const hasField =
        fieldName =>
            Object.prototype.hasOwnProperty.call(
                data,
                fieldName
            );


    const updatedData = {

        updatedBy:
            userId

    };


    const finalEnterprise =
        hasField("enterprise")

            ? data.enterprise

            : existingMember.enterprise;


    const finalBeneficiary =
        hasField("beneficiary")

            ? data.beneficiary

            : existingMember.beneficiary;


    if (
        hasField("enterprise")
    ) {

        await verifyEnterprise(

            data.enterprise,

            organizationId

        );


        updatedData.enterprise =
            data.enterprise;

    }


    if (
        hasField("beneficiary")
    ) {

        await verifyBeneficiary(

            data.beneficiary,

            organizationId

        );


        updatedData.beneficiary =
            data.beneficiary;

    }


    if (
        hasField("enterprise") ||
        hasField("beneficiary")
    ) {

        const duplicate =
            await EnterpriseMember.findOne({

                organization:
                    organizationId,

                enterprise:
                    finalEnterprise,

                beneficiary:
                    finalBeneficiary,

                isDeleted:
                    false,

                _id: {

                    $ne:
                        memberId

                }

            });


        if (duplicate) {

            const error =
                new Error(
                    "Beneficiary is already a member of this enterprise"
                );

            error.statusCode = 409;

            throw error;

        }

    }


    if (
        hasField("memberRole")
    ) {

        updatedData.memberRole =
            validateMemberRole(

                data.memberRole

            );

    }


    if (
        hasField("status")
    ) {

        updatedData.status =
            validateMembershipStatus(

                data.status

            );

    }


    if (
        hasField("joinedDate")
    ) {

        updatedData.joinedDate =
            data.joinedDate;

    }


    if (
        hasField("leftDate")
    ) {

        updatedData.leftDate =
            data.leftDate;

    }


    if (
        hasField("customFields")
    ) {

        updatedData.customFields =
            await processCustomFields(

                data.customFields,

                organizationId,

                false,

                "EnterpriseMember"

            );

    }


    const member =
        await EnterpriseMember.findOneAndUpdate(

            {

                _id:
                    memberId,

                organization:
                    organizationId,

                isDeleted:
                    false

            },

            {

                $set:
                    updatedData

            },

            {

                new:
                    true,

                runValidators:
                    true

            }

        );


    if (!member) {

        const error =
            new Error(
                "Enterprise member not found"
            );

        error.statusCode = 404;

        throw error;

    }


    return await populateMember(

        EnterpriseMember.findById(
            member._id
        )

    );

};


// =====================================================
// DELETE ENTERPRISE MEMBER
// =====================================================

const deleteEnterpriseMember = async (
    memberId,
    organizationId,
    userId
) => {

    const member =
        await EnterpriseMember.findOneAndUpdate(

            {

                _id:
                    memberId,

                organization:
                    organizationId,

                isDeleted:
                    false

            },

            {

                $set: {

                    isDeleted:
                        true,

                    deletedAt:
                        new Date(),

                    deletedBy:
                        userId,

                    status:
                        "Inactive",

                    leftDate:
                        new Date(),

                    updatedBy:
                        userId

                }

            },

            {

                new:
                    true

            }

        );


    if (!member) {

        const error =
            new Error(
                "Enterprise member not found"
            );

        error.statusCode = 404;

        throw error;

    }


    return member;

};


// =====================================================
// GET ENTERPRISES BY BENEFICIARY
// =====================================================

const getEnterprisesByMember = async (
    beneficiaryId,
    organizationId
) => {

    await verifyBeneficiary(

        beneficiaryId,

        organizationId

    );


    return await populateMember(

        EnterpriseMember.find({

            organization:
                organizationId,

            beneficiary:
                beneficiaryId,

            isDeleted:
                false,

            status:
                "Active"

        })

        .sort({

            createdAt:
                -1

        })

    );

};


// =====================================================
// EXPORT
// =====================================================

module.exports = {

    createEnterpriseMember,

    getEnterpriseMembers,

    getEnterpriseMemberById,

    updateEnterpriseMember,

    deleteEnterpriseMember,

    getMembersByEnterprise,

    getEnterprisesByMember

};