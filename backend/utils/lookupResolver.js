const mongoose = require("mongoose");

const Lookup = require("../models/Lookup");


// =====================================================
// ESCAPE REGEX
// =====================================================
//
// Escapes special regex characters so lookup values such as:
//
// A+
// A.
// A*
// (test)
//
// are searched as literal text.
//

const escapeRegex = (value) => {

    return String(value).replace(
        /[.*+?^${}()|[\]\\]/g,
        "\\$&"
    );

};


// =====================================================
// RESOLVE LOOKUP
// =====================================================
//
// Accepts:
//
// 1. Lookup ObjectId
// 2. Lookup value
// 3. Lookup code
//
// Example:
//
// resolveLookup(
//     organizationId,
//     "Beneficiary",
//     "Gender",
//     "male"
// )
//
// OR:
//
// resolveLookup(
//     organizationId,
//     "Beneficiary",
//     "Gender",
//     "MALE"
// )
//
// OR:
//
// resolveLookup(
//     organizationId,
//     "Beneficiary",
//     "Gender",
//     lookupId
// )
//
// Returns:
//
// Lookup ObjectId
//
// IMPORTANT:
//
// The lookup MUST belong to:
//
// - current organization
// - requested module
// - requested category
// - active lookup
//
// =====================================================

const resolveLookup = async (
    organizationId,
    module,
    category,
    value
) => {

    // =================================================
    // EMPTY VALUE
    // =================================================

    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {

        return null;

    }


    // =================================================
    // VALIDATE MODULE
    // =================================================

    const normalizedModule =
        String(module || "").trim();


    if (!normalizedModule) {

        throw new Error(
            "Lookup module is required"
        );

    }


    // =================================================
    // VALIDATE CATEGORY
    // =================================================

    const normalizedCategory =
        String(category || "").trim();


    if (!normalizedCategory) {

        throw new Error(
            "Lookup category is required"
        );

    }


    // =================================================
    // NORMALIZE VALUE
    // =================================================

    const normalizedValue =
        typeof value === "string"
            ? value.trim()
            : value;


    // =================================================
    // OBJECT ID
    // =================================================
    //
    // If the frontend sends a Lookup _id,
    // verify that the lookup belongs to:
    //
    // organization
    // module
    // category
    // active = true
    //
    // =================================================

    if (
        typeof normalizedValue === "string" &&
        mongoose.Types.ObjectId.isValid(
            normalizedValue
        )
    ) {

        const lookup =
            await Lookup.findOne({

                _id:
                    normalizedValue,

                organization:
                    organizationId,

                module: {

                    $regex:
                        `^${escapeRegex(
                            normalizedModule
                        )}$`,

                    $options:
                        "i"

                },

                category: {

                    $regex:
                        `^${escapeRegex(
                            normalizedCategory
                        )}$`,

                    $options:
                        "i"

                },

                active:
                    true

            });


        // -------------------------------------------------
        // INVALID OBJECT ID LOOKUP
        // -------------------------------------------------

        if (!lookup) {

            throw new Error(

                `${normalizedModule}/${normalizedCategory} lookup not found or does not belong to this organization: ${normalizedValue}`

            );

        }


        return lookup._id;

    }


    // =================================================
    // TEXT VALUE / CODE
    // =================================================

    if (
        typeof normalizedValue !== "string"
    ) {

        throw new Error(

            `Invalid ${normalizedModule}/${normalizedCategory} lookup value`

        );

    }


    // =================================================
    // FIND BY VALUE OR CODE
    // =================================================
    //
    // The frontend may send either:
    //
    // value:
    // "female"
    //
    // OR code:
    // "FEMALE"
    //
    // Both resolve to the same Lookup _id.
    //
    // =================================================

    const lookup =
        await Lookup.findOne({

            organization:
                organizationId,

            module: {

                $regex:
                    `^${escapeRegex(
                        normalizedModule
                    )}$`,

                $options:
                    "i"

            },

            category: {

                $regex:
                    `^${escapeRegex(
                        normalizedCategory
                    )}$`,

                $options:
                    "i"

            },

            $or: [

                {

                    value: {

                        $regex:
                            `^${escapeRegex(
                                normalizedValue
                            )}$`,

                        $options:
                            "i"

                    }

                },

                {

                    code: {

                        $regex:
                            `^${escapeRegex(
                                normalizedValue
                            )}$`,

                        $options:
                            "i"

                    }

                }

            ],

            active:
                true

        });


    // =================================================
    // NOT FOUND
    // =================================================

    if (!lookup) {

        throw new Error(

            `${normalizedModule}/${normalizedCategory} lookup not found: ${normalizedValue}`

        );

    }


    // =================================================
    // RETURN LOOKUP ID
    // =================================================

    return lookup._id;

};


// =====================================================
// EXPORT
// =====================================================

module.exports =
    resolveLookup;