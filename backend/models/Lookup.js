const mongoose = require("mongoose");

const {
    normalizeModule,
    getLookupCategoriesByModule
} = require("../config/systemLookupFields");


// =====================================================
// HELPERS
// =====================================================

const normalizeCategory = (value) => {

    if (
        value === undefined ||
        value === null
    ) {

        return "";

    }

    return String(value).trim();

};


const normalizeValue = (value) => {

    if (
        value === undefined ||
        value === null
    ) {

        return "";

    }

    return String(value).trim();

};


const normalizeCode = (value) => {

    if (
        value === undefined ||
        value === null
    ) {

        return "";

    }

    return String(value)
        .trim()
        .toUpperCase();

};


const normalizeSemanticType = (value) => {

    if (
        value === undefined ||
        value === null ||
        value === ""
    ) {

        return null;

    }

    const normalized =
        String(value)
            .trim()
            .toLowerCase();

    if (
        normalized === "monetary"
    ) {

        return "monetary";

    }

    if (
        normalized === "physical"
    ) {

        return "physical";

    }

    return null;

};


// =====================================================
// ALLOCATION BEHAVIOR
// =====================================================
//
// Used only by:
//
// module: ServiceDelivery
// category: ServiceType
//
// CONSUMPTION:
// Delivered quantity is a shared consumable pool.
//
// PARTICIPATION:
// Delivered quantity represents participation in
// the service/activity and may be counted independently
// for each beneficiary.
//
// =====================================================

const normalizeAllocationBehavior = (value) => {

    if (
        value === undefined ||
        value === null ||
        value === ""
    ) {

        return null;

    }

    const normalized =
        String(value)
            .trim()
            .toUpperCase();

    if (
        normalized === "CONSUMPTION"
    ) {

        return "CONSUMPTION";

    }

    if (
        normalized === "PARTICIPATION"
    ) {

        return "PARTICIPATION";

    }

    return null;

};


const normalizeAllowedUnits = (value) => {

    if (
        value === undefined ||
        value === null
    ) {

        return [];

    }

    if (
        !Array.isArray(value)
    ) {

        return value;

    }

    const normalized = [];

    const seen =
        new Set();

    for (
        const item
        of value
    ) {

        let id = null;

        if (
            item &&
            typeof item === "object" &&
            item._id
        ) {

            id = item._id;

        }
        else {

            id = item;

        }

        if (
            !id
        ) {

            continue;

        }

        const stringId =
            String(id);

        if (
            seen.has(stringId)
        ) {

            continue;

        }

        seen.add(
            stringId
        );

        normalized.push(
            id
        );

    }

    return normalized;

};


// =====================================================
// SCHEMA
// =====================================================

const LookupSchema =
    new mongoose.Schema(

        {

            organization: {

                type:
                    mongoose.Schema.Types.ObjectId,

                ref:
                    "Organization",

                required:
                    true,

                index:
                    true

            },


            module: {

                type:
                    String,

                required:
                    true,

                trim:
                    true,

                set:
                    normalizeModule,

                index:
                    true

            },


            category: {

                type:
                    String,

                required:
                    true,

                trim:
                    true,

                set:
                    normalizeCategory,

                index:
                    true

            },


            value: {

                type:
                    String,

                required:
                    true,

                trim:
                    true,

                set:
                    normalizeValue

            },


            code: {

                type:
                    String,

                default:
                    "",

                trim:
                    true,

                set:
                    normalizeCode

            },


            // =================================================
            // UNIT SEMANTIC TYPE
            // =================================================
            //
            // Used only by:
            //
            // module: ServiceDelivery
            // category: Unit
            //
            // monetary:
            // Amount, ETB, Birr, Money, Cash, etc.
            //
            // physical:
            // Box, Kg, Pair, Day, Session, Pack, etc.
            //
            // =================================================

            semanticType: {

                type:
                    String,

                enum: [

                    "monetary",

                    "physical",

                    null

                ],

                default:
                    null,

                set:
                    normalizeSemanticType

            },


            // =================================================
            // SERVICE TYPE ALLOCATION BEHAVIOR
            // =================================================
            //
            // Used only by:
            //
            // module: ServiceDelivery
            // category: ServiceType
            //
            // CONSUMPTION:
            // Delivered quantity is a shared pool that can
            // be consumed by beneficiaries.
            //
            // PARTICIPATION:
            // Delivered quantity represents participation
            // opportunities and can be counted independently
            // for beneficiaries.
            //
            // =================================================

            allocationBehavior: {

                type:
                    String,

                enum: [

                    "CONSUMPTION",

                    "PARTICIPATION",

                    null

                ],

                default:
                    null,

                set:
                    normalizeAllocationBehavior

            },


            // =================================================
            // SERVICE TYPE -> ALLOWED UNITS
            // =================================================
            //
            // Used only by:
            //
            // module: ServiceDelivery
            // category: ServiceType
            //
            // Each ObjectId must reference:
            //
            // module: ServiceDelivery
            // category: Unit
            //
            // There is intentionally NO defaultUnit.
            //
            // =================================================

            allowedUnits: [
                {
                    type:
                        mongoose.Schema.Types.ObjectId,
                    ref:
                        "Lookup"
                }
            ],

            // =================================================
            // SERVICE TYPE -> ALLOWED RECIPIENTS
            // =================================================
            //
            // Who this service can be given to. Empty = anyone.
            // Cash assistance, for example, goes to people and
            // households, not to institutions (that is a grant).
            //
            // =================================================
            recipientTypes: [
                {
                    type: String,
                    enum: ["Individual", "Household", "Group / Community", "Institution"]
                }
            ],


            // =================================================
            // PARENT LOOKUP
            // =================================================
            //
            // ServiceType -> ServiceCategory
            //
            // =================================================

            parentLookup: {

                type:
                    mongoose.Schema.Types.ObjectId,

                ref:
                    "Lookup",

                default:
                    null,

                index:
                    true

            },


            isSystemDefault: {

                type:
                    Boolean,

                default:
                    false,

                index:
                    true

            },


            active: {

                type:
                    Boolean,

                default:
                    true,

                index:
                    true

            },


            createdBy: {

                type:
                    mongoose.Schema.Types.ObjectId,

                ref:
                    "User",

                default:
                    null

            },


            updatedBy: {

                type:
                    mongoose.Schema.Types.ObjectId,

                ref:
                    "User",

                default:
                    null

            }

        },

        {

            timestamps:
                true

        }

    );


// =====================================================
// PRE VALIDATE
// =====================================================
//
// IMPORTANT:
//
// This is an async middleware.
// Do NOT use next() here.
//
// Errors are thrown and Mongoose handles them.
// =====================================================

LookupSchema.pre(
    "validate",
    async function() {

        this.module =
            normalizeModule(
                this.module
            );

        this.category =
            normalizeCategory(
                this.category
            );

        this.value =
            normalizeValue(
                this.value
            );

        this.code =
            normalizeCode(
                this.code
            );

        this.semanticType =
            normalizeSemanticType(
                this.semanticType
            );

        this.allocationBehavior =
            normalizeAllocationBehavior(
                this.allocationBehavior
            );

        this.allowedUnits =
            normalizeAllowedUnits(
                this.allowedUnits
            );


        // -------------------------------------------------
        // VALIDATE MODULE
        // -------------------------------------------------

        const categories =
            getLookupCategoriesByModule(
                this.module
            );


        if (
            !Array.isArray(categories)
        ) {

            throw new Error(
                `Lookup module "${this.module}" is not configured.`
            );

        }


        // -------------------------------------------------
        // VALIDATE CATEGORY
        // -------------------------------------------------

        const categoryDefinition =
            categories.find(

                item =>
                    item ===
                    this.category

            );


        if (
            !categoryDefinition
        ) {

            throw new Error(
                `Lookup category "${this.category}" is not allowed for module "${this.module}".`
            );

        }


        // -------------------------------------------------
        // SERVICE DELIVERY UNIT
        // -------------------------------------------------

        if (
            this.module ===
                "ServiceDelivery" &&
            this.category ===
                "Unit"
        ) {

            if (
                !this.semanticType
            ) {

                throw new Error(
                    "Service Delivery Unit semantic type is required."
                );

            }


            if (
                !this.code
            ) {

                throw new Error(
                    "Service Delivery Unit code is required."
                );

            }


            // Units never have allocation behavior.

            this.allocationBehavior =
                null;


            this.allowedUnits =
                [];

        }


        // -------------------------------------------------
        // NON-UNIT LOOKUPS
        // -------------------------------------------------

        if (
            !(
                this.module ===
                    "ServiceDelivery" &&
                this.category ===
                    "Unit"
            )
        ) {

            this.semanticType =
                null;

        }


        // -------------------------------------------------
        // SERVICE CATEGORY
        // -------------------------------------------------

        if (
            this.module ===
                "ServiceDelivery" &&
            this.category ===
                "ServiceCategory"
        ) {

            if (
                this.parentLookup
            ) {

                throw new Error(
                    "Service Category cannot have a parent lookup."
                );

            }


            // Service Categories never have
            // allocation behavior.

            this.allocationBehavior =
                null;


            this.allowedUnits =
                [];

        }


        // -------------------------------------------------
        // SERVICE TYPE
        // -------------------------------------------------

        if (
            this.module ===
                "ServiceDelivery" &&
            this.category ===
                "ServiceType"
        ) {

            if (
                !this.parentLookup
            ) {

                throw new Error(
                    "Service Type must belong to a Service Category."
                );

            }


            if (
                !mongoose.Types.ObjectId.isValid(
                    this.parentLookup
                )
            ) {

                throw new Error(
                    "Service Type parent category is invalid."
                );

            }


            // -------------------------------------------------
            // ALLOCATION BEHAVIOR
            // -------------------------------------------------
            //
            // Existing Service Types that do not yet have
            // allocationBehavior are treated as CONSUMPTION
            // for backward compatibility.
            //
            // New configuration should explicitly provide
            // either CONSUMPTION or PARTICIPATION.
            //
            // -------------------------------------------------

            if (
                !this.allocationBehavior
            ) {

                this.allocationBehavior =
                    "CONSUMPTION";

            }


            if (
                ![
                    "CONSUMPTION",
                    "PARTICIPATION"
                ].includes(
                    this.allocationBehavior
                )
            ) {

                throw new Error(
                    "Service Type allocation behavior must be either CONSUMPTION or PARTICIPATION."
                );

            }


            if (
                !Array.isArray(
                    this.allowedUnits
                ) ||
                this.allowedUnits.length === 0
            ) {

                throw new Error(
                    "Service Type must have at least one allowed unit."
                );

            }


            const uniqueAllowedUnitIds =
                new Set(

                    this.allowedUnits.map(

                        unit =>
                            String(unit)

                    )

                );


            if (
                uniqueAllowedUnitIds.size !==
                this.allowedUnits.length
            ) {

                throw new Error(
                    "Service Type allowed units must be unique."
                );

            }


            for (
                const unitId
                of this.allowedUnits
            ) {

                if (
                    !mongoose.Types.ObjectId.isValid(
                        unitId
                    )
                ) {

                    throw new Error(
                        "One or more Service Type allowed units are invalid."
                    );

                }

            }

        }


        // -------------------------------------------------
        // ALL OTHER LOOKUPS
        // -------------------------------------------------

        if (
            !(
                this.module ===
                    "ServiceDelivery" &&
                this.category ===
                    "ServiceType"
            )
        ) {

            this.allowedUnits =
                [];

            this.allocationBehavior =
                null;

        }

    }

);


// =====================================================
// INDEXES
// =====================================================

LookupSchema.index({

    organization:
        1,

    module:
        1,

    category:
        1,

    value:
        1

}, {

    unique:
        true

});


LookupSchema.index({

    organization:
        1,

    module:
        1,

    category:
        1,

    code:
        1

}, {

    unique:
        true,

    partialFilterExpression: {

        code: {

            // a non-empty code ($gt "" instead of $ne "":
            // Atlas does not accept $ne in a partial index)
            $type:
                "string",

            $gt:
                ""

        }

    }

});


LookupSchema.index({

    organization:
        1,

    module:
        1,

    category:
        1

});


LookupSchema.index({

    organization:
        1,

    module:
        1,

    category:
        1,

    active:
        1

});


LookupSchema.index({

    organization:
        1,

    parentLookup:
        1

});


LookupSchema.index({

    organization:
        1,

    module:
        1,

    category:
        1,

    semanticType:
        1

});


LookupSchema.index({

    organization:
        1,

    module:
        1,

    category:
        1,

    allocationBehavior:
        1

});


LookupSchema.index({

    organization:
        1,

    isSystemDefault:
        1

});


// =====================================================
// EXPORT
// =====================================================

module.exports =
    mongoose.model(
        "Lookup",
        LookupSchema
    );