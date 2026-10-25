const generateSequence =
    require("../utils/generateSequence");

const queryHelper =
    require("../utils/queryHelper");

const resolveLookup =
    require("../utils/lookupResolver");

const {
    processCustomFields
} =
    require("../utils/customFieldProcessor");

const Enterprise =
    require("../models/Enterprise");

const EnterpriseMember =
    require("../models/EnterpriseMember");

const Beneficiary =
    require("../models/Beneficiary");


// ==========================================================
// ENTERPRISE LOOKUP CATEGORIES
// ==========================================================

const ENTERPRISE_MODULE =
    "Enterprise";

const ENTERPRISE_LOOKUP_CATEGORIES = {

    ENTERPRISE_TYPE:
        "EnterpriseType",

    OWNERSHIP_TYPE:
        "OwnershipType",

    BUSINESS_SECTOR:
        "BusinessSector"

};


// ==========================================================
// RESOLVE OPTIONAL ENTERPRISE LOOKUP
// ==========================================================

const resolveEnterpriseLookup = async (
    organizationId,
    category,
    value
) => {

    // ------------------------------------------------------
    // EMPTY
    // ------------------------------------------------------

    if (
        value === undefined ||
        value === null ||
        value === ""
    ) {

        return null;

    }


    // ------------------------------------------------------
    // RESOLVE
    // ------------------------------------------------------

    return await resolveLookup(

        organizationId,

        ENTERPRISE_MODULE,

        category,

        value

    );

};


// ==========================================================
// VERIFY BENEFICIARY
// ==========================================================

const verifyBeneficiary = async (
    beneficiaryId,
    organizationId
) => {

    if (!beneficiaryId) {

        throw new Error(
            "Beneficiary is required"
        );

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

        throw new Error(
            "Beneficiary not found or does not belong to this organization"
        );

    }


    return beneficiary;

};


// ==========================================================
// VERIFY ENTERPRISE
// ==========================================================

const verifyEnterprise = async (
    enterpriseId,
    organizationId
) => {

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

        throw new Error(
            "Enterprise not found"
        );

    }


    return enterprise;

};


// ==========================================================
// CREATE ENTERPRISE
// ==========================================================

const createEnterprise = async (
    data,
    organizationId,
    userId
) => {

    const {

        customFields = [],

        beneficiaries = [],

        ...enterpriseData

    } = data;


    // ------------------------------------------------------
    // CUSTOM FIELDS
    // ------------------------------------------------------

    const savedCustomFields =
        await processCustomFields(

            customFields,

            organizationId,

            true,

            "Enterprise"

        );


    // ------------------------------------------------------
    // ENTERPRISE TYPE
    // ------------------------------------------------------

    const enterpriseType =
        await resolveEnterpriseLookup(

            organizationId,

            ENTERPRISE_LOOKUP_CATEGORIES.ENTERPRISE_TYPE,

            enterpriseData.enterpriseType

        );


    // ------------------------------------------------------
    // OWNERSHIP TYPE
    // ------------------------------------------------------

    const ownershipType =
        await resolveEnterpriseLookup(

            organizationId,

            ENTERPRISE_LOOKUP_CATEGORIES.OWNERSHIP_TYPE,

            enterpriseData.ownershipType

        );


    // ------------------------------------------------------
    // BUSINESS SECTOR
    // ------------------------------------------------------

    const businessSector =
        await resolveEnterpriseLookup(

            organizationId,

            ENTERPRISE_LOOKUP_CATEGORIES.BUSINESS_SECTOR,

            enterpriseData.businessSector

        );


    // ------------------------------------------------------
    // STATUS
    // ------------------------------------------------------
    //
    // Status is currently NOT a system lookup category
    // for Enterprise.
    //
    // Keep the value if supplied, otherwise null.
    //
    // ------------------------------------------------------

    const status =
        enterpriseData.status !== undefined
            ? enterpriseData.status
            : null;


    // ------------------------------------------------------
    // ENTERPRISE NUMBER
    // ------------------------------------------------------

    const enterpriseNumber =
        await generateSequence(

            "Enterprise",

            "ENT",

            organizationId

        );


    // ------------------------------------------------------
    // CREATE
    // ------------------------------------------------------

    const enterprise =
        await Enterprise.create({

            ...enterpriseData,

            enterpriseNumber,

            organization:
                organizationId,

            createdBy:
                userId,

            enterpriseType,

            status,

            ownershipType,

            businessSector,

            customFields:
                savedCustomFields

        });


    // ------------------------------------------------------
    // INITIAL MEMBERS
    // ------------------------------------------------------

    if (
        Array.isArray(beneficiaries) &&
        beneficiaries.length > 0
    ) {

        const uniqueBeneficiaries =
            [
                ...new Set(

                    beneficiaries.map(

                        item =>

                            String(

                                typeof item === "object"

                                    ? item.beneficiary

                                    : item

                            )

                    )

                )

            ];


        for (
            const beneficiaryId
            of uniqueBeneficiaries
        ) {

            await verifyBeneficiary(

                beneficiaryId,

                organizationId

            );


            await EnterpriseMember.create({

                organization:
                    organizationId,

                enterprise:
                    enterprise._id,

                beneficiary:
                    beneficiaryId,

                createdBy:
                    userId

            });

        }

    }


    return enterprise;

};


// ==========================================================
// GET ALL ENTERPRISES
// ==========================================================

const getEnterprises = async (
    organizationId,
    reqQuery
) => {

    const query = {
        ...reqQuery
    };


    delete query.beneficiary;


    // ------------------------------------------------------
    // ENTERPRISE TYPE
    // ------------------------------------------------------

    if (
        query.enterpriseType !== undefined &&
        query.enterpriseType !== null &&
        query.enterpriseType !== ""
    ) {

        query.enterpriseType =
            await resolveEnterpriseLookup(

                organizationId,

                ENTERPRISE_LOOKUP_CATEGORIES.ENTERPRISE_TYPE,

                query.enterpriseType

            );

    }


    // ------------------------------------------------------
    // OWNERSHIP TYPE
    // ------------------------------------------------------

    if (
        query.ownershipType !== undefined &&
        query.ownershipType !== null &&
        query.ownershipType !== ""
    ) {

        query.ownershipType =
            await resolveEnterpriseLookup(

                organizationId,

                ENTERPRISE_LOOKUP_CATEGORIES.OWNERSHIP_TYPE,

                query.ownershipType

            );

    }


    // ------------------------------------------------------
    // BUSINESS SECTOR
    // ------------------------------------------------------

    if (
        query.businessSector !== undefined &&
        query.businessSector !== null &&
        query.businessSector !== ""
    ) {

        query.businessSector =
            await resolveEnterpriseLookup(

                organizationId,

                ENTERPRISE_LOOKUP_CATEGORIES.BUSINESS_SECTOR,

                query.businessSector

            );

    }


    // ------------------------------------------------------
    // QUERY
    // ------------------------------------------------------

    return await queryHelper({

        model:
            Enterprise,

        organizationId,

        reqQuery:
            query,

        searchableFields: [

            "enterpriseNumber",

            "name",

            "description",

            "phone",

            "email",

            "country",

            "region",

            "zone",

            "woreda",

            "kebele"

        ],

        populate: [

            {
                path:
                    "enterpriseType",

                select:
                    "value code"

            },

            {
                path:
                    "status",

                select:
                    "value code"

            },

            {
                path:
                    "ownershipType",

                select:
                    "value code"

            },

            {
                path:
                    "businessSector",

                select:
                    "value code"

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


// ==========================================================
// GET ENTERPRISE BY ID
// ==========================================================

const getEnterpriseById = async (
    id,
    organizationId
) => {

    const enterprise =
        await Enterprise.findOne({

            _id:
                id,

            organization:
                organizationId,

            isDeleted:
                false

        })

        .populate(
            "enterpriseType",
            "value code"
        )

        .populate(
            "status",
            "value code"
        )

        .populate(
            "ownershipType",
            "value code"
        )

        .populate(
            "businessSector",
            "value code"
        )

        .populate({

            path:
                "customFields.fieldId",

            select:
                "label key type options required placeholder validation active module"

        });


    if (!enterprise) {

        throw new Error(
            "Enterprise not found"
        );

    }


    return enterprise;

};


// ==========================================================
// UPDATE ENTERPRISE
// ==========================================================

const updateEnterprise = async (
    id,
    data,
    organizationId,
    userId
) => {

    await verifyEnterprise(

        id,

        organizationId

    );


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


    // ------------------------------------------------------
    // SCALAR FIELDS
    // ------------------------------------------------------

    const editableScalarFields = [

        "name",

        "description",

        "startDate",

        "endDate",

        "country",

        "region",

        "zone",

        "woreda",

        "regionCode",

        "zoneCode",

        "woredaCode",

        "kebele",

        "address",

        "phone",

        "email"

    ];


    editableScalarFields.forEach(

        fieldName => {

            if (
                hasField(fieldName)
            ) {

                updatedData[fieldName] =
                    data[fieldName];

            }

        }

    );


    // ------------------------------------------------------
    // ENTERPRISE TYPE
    // ------------------------------------------------------

    if (
        hasField("enterpriseType")
    ) {

        updatedData.enterpriseType =
            await resolveEnterpriseLookup(

                organizationId,

                ENTERPRISE_LOOKUP_CATEGORIES.ENTERPRISE_TYPE,

                data.enterpriseType

            );

    }


    // ------------------------------------------------------
    // OWNERSHIP TYPE
    // ------------------------------------------------------

    if (
        hasField("ownershipType")
    ) {

        updatedData.ownershipType =
            await resolveEnterpriseLookup(

                organizationId,

                ENTERPRISE_LOOKUP_CATEGORIES.OWNERSHIP_TYPE,

                data.ownershipType

            );

    }


    // ------------------------------------------------------
    // BUSINESS SECTOR
    // ------------------------------------------------------

    if (
        hasField("businessSector")
    ) {

        updatedData.businessSector =
            await resolveEnterpriseLookup(

                organizationId,

                ENTERPRISE_LOOKUP_CATEGORIES.BUSINESS_SECTOR,

                data.businessSector

            );

    }


    // ------------------------------------------------------
    // STATUS
    // ------------------------------------------------------

    if (
        hasField("status")
    ) {

        updatedData.status =
            data.status;

    }


    // ------------------------------------------------------
    // CUSTOM FIELDS
    // ------------------------------------------------------

    if (
        hasField("customFields")
    ) {

        updatedData.customFields =
            await processCustomFields(

                data.customFields,

                organizationId,

                false,

                "Enterprise"

            );

    }


    // ------------------------------------------------------
    // UPDATE
    // ------------------------------------------------------

    const enterprise =
        await Enterprise.findOneAndUpdate(

            {

                _id:
                    id,

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


    if (!enterprise) {

        throw new Error(
            "Enterprise not found"
        );

    }


    return enterprise;

};


// ==========================================================
// DELETE ENTERPRISE
// ==========================================================

const deleteEnterprise = async (
    id,
    organizationId,
    userId
) => {

    const enterprise =
        await Enterprise.findOneAndUpdate(

            {

                _id:
                    id,

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
                        userId

                }

            },

            {

                new:
                    true

            }

        );


    if (!enterprise) {

        throw new Error(
            "Enterprise not found"
        );

    }


    // ------------------------------------------------------
    // SOFT DELETE MEMBERS
    // ------------------------------------------------------

    await EnterpriseMember.updateMany(

        {

            enterprise:
                enterprise._id,

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
                    userId

            }

        }

    );


    return enterprise;

};


// ==========================================================
// ENTERPRISE LOOKUP
// ==========================================================

const getEnterpriseLookup = async (
    organizationId,
    beneficiaryId = null
) => {

    const query = {

        organization:
            organizationId,

        isDeleted:
            false

    };


    if (beneficiaryId) {

        await verifyBeneficiary(

            beneficiaryId,

            organizationId

        );


        const memberships =
            await EnterpriseMember.find({

                organization:
                    organizationId,

                beneficiary:
                    beneficiaryId,

                isDeleted:
                    false,

                status:
                    "Active"

            }).select(
                "enterprise"
            );


        query._id = {

            $in:

                memberships.map(

                    item =>
                        item.enterprise

                )

        };

    }


    return await Enterprise.find(

        query,

        {

            enterpriseNumber:
                1,

            name:
                1,

            status:
                1,

            // forms show the dates a membership must fall in
            startDate:
                1,

            endDate:
                1

        }

    )

    .populate(

        "status",

        "value code"

    )

    .sort({

        name:
            1

    });

};


// ==========================================================
// GET ENTERPRISES BY BENEFICIARY
// ==========================================================

const getEnterprisesByBeneficiary = async (
    beneficiaryId,
    organizationId
) => {

    await verifyBeneficiary(

        beneficiaryId,

        organizationId

    );


    const memberships =
        await EnterpriseMember.find({

            organization:
                organizationId,

            beneficiary:
                beneficiaryId,

            isDeleted:
                false,

            status:
                "Active"

        })

        .populate({

            path:
                "enterprise",

            match: {

                organization:
                    organizationId,

                isDeleted:
                    false

            }

        });


    return memberships

        .filter(

            member =>
                member.enterprise

        )

        .map(

            member =>
                member.enterprise

        );

};


// ==========================================================
// EXPORT
// ==========================================================

module.exports = {

    createEnterprise,

    getEnterprises,

    getEnterpriseById,

    updateEnterprise,

    deleteEnterprise,

    getEnterpriseLookup,

    getEnterprisesByBeneficiary

};