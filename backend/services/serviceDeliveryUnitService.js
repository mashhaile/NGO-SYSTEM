const mongoose =
    require("mongoose");

const Lookup =
    require("../models/Lookup");

const {
    SERVICE_DELIVERY_UNIT_DEFINITIONS
} =
    require("../config/serviceDeliveryUnits");

const ApiError =
    require("../utils/apiError");


// =====================================================
// VALIDATE ORGANIZATION ID
// =====================================================

const validateOrganizationId = (
    organizationId
) => {

    if (!organizationId) {

        throw new ApiError(
            "Organization ID is required.",
            400
        );

    }


    if (
        !mongoose.Types.ObjectId.isValid(
            organizationId
        )
    ) {

        throw new ApiError(
            "Invalid Organization ID.",
            400
        );

    }

};


// =====================================================
// BUILD STANDARD UNIT DOCUMENT
// =====================================================

const buildStandardUnitDocument = (
    organizationId,
    definition,
    userId = null
) => {

    return {

        organization:
            organizationId,

        module:
            "ServiceDelivery",

        category:
            "Unit",

        value:
            definition.value,

        code:
            definition.code,

        semanticType:
            definition.semanticType,

        isSystemDefault:
            true,

        active:
            true,

        createdBy:
            userId,

        updatedBy:
            userId

    };

};


// =====================================================
// SEED STANDARD SERVICE DELIVERY UNITS
// =====================================================
//
// IMPORTANT:
//
// - Creates only missing standard units.
// - Never deletes units.
// - Never replaces custom units.
// - Never overwrites an existing standard unit's value.
// - Repairs semanticType only for existing system-default
//   units when the semantic type is missing.
// - Safe to run repeatedly.
// =====================================================

const seedOrganizationServiceDeliveryUnits = async (
    organizationId,
    userId = null
) => {


 


    validateOrganizationId(
        organizationId
    );


    if (
        !Array.isArray(
            SERVICE_DELIVERY_UNIT_DEFINITIONS
        )
    ) {

        throw new ApiError(
            "Service Delivery Unit definitions are not configured correctly.",
            500
        );

    }


    const operations = [];


    for (
        const definition
        of SERVICE_DELIVERY_UNIT_DEFINITIONS
    ) {

        if (
            !definition ||
            !definition.code ||
            !definition.value ||
            !definition.semanticType ||
            // duplicates of another unit are not seeded
            definition.legacy
        ) {

            continue;

        }


        const standardUnit =
            buildStandardUnitDocument(

                organizationId,

                definition,

                userId

            );


        // =============================================
        // CREATE MISSING STANDARD UNIT
        // =============================================

        operations.push({

            updateOne: {

                filter: {

                    organization:
                        organizationId,

                    module:
                        "ServiceDelivery",

                    category:
                        "Unit",

                    code:
                        definition.code

                },

                update: {

                    $setOnInsert:
                        standardUnit

                },

                upsert:
                    true

            }

        });

    }


   if (operations.length > 0) {

    await Lookup.bulkWrite(
        operations,
        {
            ordered: true
        }
    );

}

    // =================================================
    // REPAIR EXISTING SYSTEM DEFAULTS
    // =================================================
    //
    // We intentionally do NOT update arbitrary custom
    // units.
    //
    // Only records already marked as system defaults are
    // eligible for semantic repair.
    // =================================================

    const repairOperations = [];


    for (
        const definition
        of SERVICE_DELIVERY_UNIT_DEFINITIONS
    ) {

        if (
            !definition ||
            !definition.code ||
            !definition.semanticType
        ) {

            continue;

        }


        repairOperations.push({

            updateOne: {

                filter: {

                    organization:
                        organizationId,

                    module:
                        "ServiceDelivery",

                    category:
                        "Unit",

                    code:
                        definition.code,

                    isSystemDefault:
                        true,

                    $or: [

                        {
                            semanticType:
                                null
                        },

                        {
                            semanticType:
                                ""
                        },

                        {
                            semanticType:
                                {
                                    $exists:
                                        false
                                }
                        }

                    ]

                },

                update: {

                    $set: {

                        semanticType:
                            definition.semanticType,

                        updatedBy:
                            userId

                    }

                }

            }

        });

    }


    if (
        repairOperations.length > 0
    ) {

        await Lookup.bulkWrite(
            repairOperations,
            {
                ordered: true
            }
        );

    }


    // =================================================
    // RETURN CURRENT STANDARD UNITS
    // =================================================

    const units =
        await Lookup.find({

            organization:
                organizationId,

            module:
                "ServiceDelivery",

            category:
                "Unit",

            isSystemDefault:
                true,

            active:
                true

        })

        .sort({

            value:
                1

        })

        .lean();


    return units;

};


// =====================================================
// ENSURE STANDARD UNITS EXIST
// =====================================================
//
// This is intentionally an alias with business-friendly
// naming. Other lifecycle processes can call this without
// caring whether the operation is technically a seed or
// repair.
// =====================================================

const ensureOrganizationServiceDeliveryUnits =
    async (
        organizationId,
        userId = null
    ) => {

        return seedOrganizationServiceDeliveryUnits(

            organizationId,

            userId

        );

    };


// =====================================================
// EXPORTS
// =====================================================

module.exports = {

    seedOrganizationServiceDeliveryUnits,

    ensureOrganizationServiceDeliveryUnits

};