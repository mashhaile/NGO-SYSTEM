const CustomField = require("../models/CustomField");

const Beneficiary = require("../models/Beneficiary");

const {
    assertCustomFieldKeyAllowed
} = require("../utils/customFieldReservedKeys");


// ==========================================================
// GENERATE OPTION VALUE
// ==========================================================
//
// Generates an internal value automatically from the label.
//
// Example:
//
// "Male"              -> "male"
// "Female Beneficiary" -> "female_beneficiary"
// "Person With Disability" -> "person_with_disability"
//
// If the generated value already exists in the current field,
// a unique suffix is added:
//
// male
// male_2
// male_3
//
// IMPORTANT:
// The generated value is editable until it is actually used.
// Once used by a beneficiary, it becomes locked.
// ==========================================================

const generateOptionValue = (
    label,
    existingValues = []
) => {

    let value =
        String(label || "")
            .trim()
            .toLowerCase()

            // Replace spaces with underscore
            .replace(/\s+/g, "_")

            // Remove unsupported characters
            .replace(/[^a-z0-9_]/g, "")

            // Remove duplicate underscores
            .replace(/_+/g, "_")

            // Remove underscore from beginning/end
            .replace(/^_+|_+$/g, "");


    // ======================================================
    // FALLBACK
    // ======================================================

    if (!value) {

        value = "option";

    }


    let finalValue = value;

    let counter = 2;


    // ======================================================
    // PREVENT DUPLICATE VALUES
    // ======================================================

    while (
        existingValues.includes(
            finalValue
        )
    ) {

        finalValue =
            `${value}_${counter}`;

        counter++;

    }


    return finalValue;

};


// ==========================================================
// GET USED OPTION VALUES
// ==========================================================
//
// Finds every value currently stored in Beneficiary records
// for this specific custom field.
//
// IMPORTANT:
// organizationId is always included to preserve tenant
// isolation.
// ==========================================================

const getUsedOptionValues = async (
    fieldId,
    organizationId
) => {

    const beneficiaries =
        await Beneficiary.find({

            organization:
                organizationId,

            customFields: {

                $elemMatch: {

                    fieldId:
                        fieldId

                }

            }

        })
        .select("customFields")
        .lean();


    const usedValues =
        new Set();


    for (
        const beneficiary
        of beneficiaries
    ) {

        for (
            const customField
            of beneficiary.customFields || []
        ) {

            // ------------------------------------------------
            // Only inspect the requested custom field
            // ------------------------------------------------

            if (
                String(
                    customField.fieldId
                ) !==
                String(fieldId)
            ) {

                continue;

            }


            // ------------------------------------------------
            // Ignore empty values
            // ------------------------------------------------

            if (
                customField.value === null ||
                customField.value === undefined
            ) {

                continue;

            }


            const value =
                String(
                    customField.value
                ).trim();


            if (!value) {

                continue;

            }


            usedValues.add(
                value
            );

        }

    }


    return usedValues;

};


// ==========================================================
// PREPARE FIELD FOR RESPONSE
// ==========================================================
//
// IMPORTANT:
//
// isValueLocked is NOT saved inside MongoDB.
//
// It is calculated dynamically from actual beneficiary data.
//
// Example:
//
// {
//     label: "Male",
//     value: "male",
//     isValueLocked: true
// }
//
// This allows the frontend to display the lock icon while
// keeping the database schema clean.
// ==========================================================

const prepareFieldForResponse = async (
    field,
    organizationId
) => {

    // ------------------------------------------------------
    // Non-select fields do not have option values
    // ------------------------------------------------------

    if (
        field.type !== "select"
    ) {

        return field;

    }


    const usedValues =
        await getUsedOptionValues(
            field._id,
            organizationId
        );


    const fieldObject =
        field.toObject
            ? field.toObject()
            : { ...field };


    // ======================================================
    // ADD DYNAMIC LOCK STATUS
    // ======================================================

    fieldObject.options =
        (fieldObject.options || [])
            .map(
                option => {

                    const value =
                        String(
                            option.value || ""
                        ).trim();


                    return {

                        ...option,

                        // ------------------------------------------------
                        // TRUE when this value is already used by at
                        // least one beneficiary.
                        // ------------------------------------------------

                        isValueLocked:
                            value !== "" &&
                            usedValues.has(
                                value
                            )

                    };

                }
            );


    return fieldObject;

};


// ==========================================================
// CREATE CUSTOM FIELD
// ==========================================================

const createCustomField = async (
    data,
    organizationId,
    userId
) => {

    assertCustomFieldKeyAllowed(
        data.module,
        data.key
    );

    // ======================================================
    // CHECK DUPLICATE FIELD KEY
    // ======================================================

    const existing =
        await CustomField.findOne({

            organization:
                organizationId,

            module:
                data.module,

            key:
                data.key

        });


    if (existing) {

        throw new Error(
            "Custom field already exists"
        );

    }


    // ======================================================
    // PREPARE OPTIONS
    // ======================================================

    let options = [];


    if (
        data.type === "select"
    ) {

        const inputOptions =
            Array.isArray(
                data.options
            )
                ? data.options
                : [];


        // --------------------------------------------------
        // SELECT MUST HAVE AT LEAST ONE OPTION
        // --------------------------------------------------

        if (
            inputOptions.length === 0
        ) {

            throw new Error(
                "Select field must have at least one option"
            );

        }


        const generatedValues = [];


        // ==================================================
        // GENERATE VALUES
        // ==================================================

        options =
            inputOptions.map(
                option => {

                    const label =
                        String(
                            option.label || ""
                        ).trim();


                    if (!label) {

                        throw new Error(
                            "Option label is required"
                        );

                    }


                    const value =
                        generateOptionValue(
                            label,
                            generatedValues
                        );


                    generatedValues.push(
                        value
                    );


                    return {

                        label,

                        value

                    };

                }
            );

    }
    else {

        // --------------------------------------------------
        // Non-select fields never have options
        // --------------------------------------------------

        options = [];

    }


    // ======================================================
    // CREATE
    // ======================================================

    const field =
        await CustomField.create({

            ...data,

            options,

            organization:
                organizationId,

            createdBy:
                userId

        });


    return field;

};


// ==========================================================
// GET CUSTOM FIELDS BY MODULE
// ==========================================================
//
// Returns only active fields.
//
// For select fields, every option receives a dynamic
// isValueLocked property.
// ==========================================================

const getCustomFields = async (
    organizationId,
    module
) => {

    const fields =
        await CustomField.find({

            organization:
                organizationId,

            module:
                module,

            active:
                true

        })
        .sort({

            createdAt:
                1

        });


    const result = [];


    for (
        const field
        of fields
    ) {

        result.push(

            await prepareFieldForResponse(
                field,
                organizationId
            )

        );

    }


    return result;

};


// ==========================================================
// GET CUSTOM FIELD BY ID
// ==========================================================
//
// Used by the edit page.
//
// Returns dynamic isValueLocked information.
// ==========================================================

const getCustomFieldById = async (
    id,
    organizationId
) => {

    const field =
        await CustomField.findOne({

            _id:
                id,

            organization:
                organizationId

        });


    if (!field) {

        throw new Error(
            "Custom field not found"
        );

    }

    // ======================================================
    // ADD DYNAMIC LOCK INFORMATION
    // ======================================================

    return await prepareFieldForResponse(
        field,
        organizationId
    );

};


// ==========================================================
// UPDATE CUSTOM FIELD
// ==========================================================

const updateCustomField = async (
    id,
    data,
    organizationId,
    userId
) => {

    const field =
        await CustomField.findOne({

            _id:
                id,

            organization:
                organizationId

        });


    if (!field) {

        throw new Error(
            "Custom field not found"
        );

    }


    assertCustomFieldKeyAllowed(
        field.module,
        field.key
    );


    // ======================================================
    // PROTECT IMMUTABLE FIELD CONFIGURATION
    // ======================================================
    //
    // These values define the identity/structure of the
    // custom field and must not change after creation.
    //
    // Frontend already disables them, but backend MUST also
    // enforce this because frontend restrictions can be
    // bypassed.
    // ======================================================

    if (
        data.module !== undefined &&
        data.module !== field.module
    ) {

        throw new Error(
            "Field module cannot be changed after creation."
        );

    }


    if (
        data.key !== undefined &&
        data.key !== field.key
    ) {

        throw new Error(
            "Field key cannot be changed after creation."
        );

    }


    if (
        data.type !== undefined &&
        data.type !== field.type
    ) {

        throw new Error(
            "Field type cannot be changed after creation."
        );

    }


    // ======================================================
    // REMOVE IMMUTABLE VALUES FROM UPDATE
    // ======================================================
    //
    // They are allowed to arrive from a client request only
    // if they contain the exact original value.
    //
    // We remove them before Object.assign so the database
    // cannot accidentally receive them as an update.
    // ======================================================

    delete data.module;

    delete data.key;

    delete data.type;


    // ======================================================
    // SELECT OPTION PROTECTION
    // ======================================================
    //
    // This is the most important protection.
    //
    // Once a value is used by a beneficiary:
    //
    // 1. It cannot be renamed by changing its value.
    // 2. It cannot be removed.
    // 3. It cannot be reused by another option.
    //
    // The LABEL can still change.
    //
    // Example:
    //
    // Label: "Male"
    // Value: "male"
    //
    // If "male" is used:
    //
    // Label can become:
    // "Male Beneficiary"
    //
    // But value MUST remain:
    // "male"
    // ======================================================

    if (
        field.type === "select" &&
        Array.isArray(data.options)
    ) {

        const usedValues =
            await getUsedOptionValues(
                field._id,
                organizationId
            );


        const oldOptions =
            field.options || [];


        const oldValues =
            oldOptions.map(
                option =>
                    String(
                        option.value || ""
                    ).trim()
            );


        const submittedOptions =
            data.options;


        // ==================================================
        // PROTECT USED VALUES FROM REMOVAL OR CHANGE
        // ==================================================

        for (
            const usedValue
            of usedValues
        ) {

            const oldValueExists =
                oldValues.includes(
                    usedValue
                );


            // ------------------------------------------------
            // If this value was not part of this field's
            // original options, nothing to protect here.
            // ------------------------------------------------

            if (!oldValueExists) {

                continue;

            }


            const matchingSubmittedOption =
                submittedOptions.find(
                    option =>
                        String(
                            option.value || ""
                        ).trim() ===
                        usedValue
                );


            // ------------------------------------------------
            // USED OPTION WAS REMOVED OR ITS VALUE CHANGED
            // ------------------------------------------------

            if (
                !matchingSubmittedOption
            ) {

                throw new Error(

                    `Option value "${usedValue}" is already in use and cannot be changed or removed.`

                );

            }

        }


        // ==================================================
        // PREPARE FINAL OPTIONS
        // ==================================================

        const finalValues = [];


        const finalOptions =
            submittedOptions.map(
                option => {

                    const label =
                        String(
                            option.label || ""
                        ).trim();


                    let value =
                        String(
                            option.value || ""
                        ).trim();


                    // ------------------------------------------------
                    // LABEL REQUIRED
                    // ------------------------------------------------

                    if (!label) {

                        throw new Error(
                            "Option label is required"
                        );

                    }


                    // ------------------------------------------------
                    // GENERATE VALUE IF EMPTY
                    // ------------------------------------------------

                    if (!value) {

                        value =
                            generateOptionValue(
                                label,
                                finalValues
                            );

                    }


                    // ------------------------------------------------
                    // DUPLICATE VALUE
                    // ------------------------------------------------

                    if (
                        finalValues.includes(
                            value
                        )
                    ) {

                        throw new Error(

                            `Duplicate option value "${value}" is not allowed.`

                        );

                    }


                    // ------------------------------------------------
                    // USED VALUE PROTECTION
                    // ------------------------------------------------
                    //
                    // A value already used by a beneficiary can
                    // only remain attached to the same existing
                    // option.
                    // ------------------------------------------------

                    if (
                        usedValues.has(
                            value
                        )
                    ) {

                        const oldOption =
                            oldOptions.find(
                                old =>
                                    String(
                                        old.value || ""
                                    ).trim() ===
                                    value
                            );


                        if (!oldOption) {

                            throw new Error(

                                `Option value "${value}" is already in use and cannot be reused.`

                            );

                        }

                    }


                    finalValues.push(
                        value
                    );


                    return {

                        label,

                        value

                    };

                }
            );


        // ==================================================
        // FINAL USED VALUE VERIFICATION
        // ==================================================
        //
        // Double-check every old used value.
        //
        // This protects against:
        //
        // - deletion
        // - changing the value
        // - moving the value to another option
        // ==================================================

        for (
            const oldOption
            of oldOptions
        ) {

            const oldValue =
                String(
                    oldOption.value || ""
                ).trim();


            if (!oldValue) {

                continue;

            }


            if (
                !usedValues.has(
                    oldValue
                )
            ) {

                continue;

            }


            const matchingOption =
                finalOptions.find(
                    option =>
                        option.value ===
                        oldValue
                );


            if (
                !matchingOption
            ) {

                throw new Error(

                    `Option value "${oldValue}" is already in use and cannot be changed or removed.`

                );

            }

        }


        // ==================================================
        // SAVE FINAL OPTIONS
        // ==================================================

        data.options =
            finalOptions;

    }


    // ======================================================
    // IF SOMEONE TRIES TO SEND OPTIONS FOR NON-SELECT FIELD
    // ======================================================

    if (
        field.type !== "select"
    ) {

        data.options = [];

    }


    // ======================================================
    // ALLOW ONLY EXPECTED UPDATE FIELDS
    // ======================================================
    //
    // The frontend normally sends:
    //
    // label
    // required
    // active
    // options
    //
    // We prevent accidental modification of protected
    // configuration fields.
    // ======================================================

    const allowedUpdates = {};


    if (
        data.label !== undefined
    ) {

        allowedUpdates.label =
            String(
                data.label
            ).trim();

    }


    if (
        data.required !== undefined
    ) {

        allowedUpdates.required =
            Boolean(
                data.required
            );

    }


    if (
        data.active !== undefined
    ) {

        allowedUpdates.active =
            Boolean(
                data.active
            );

    }


    if (
        data.options !== undefined
    ) {

        allowedUpdates.options =
            data.options;

    }


    // ======================================================
    // APPLY UPDATE
    // ======================================================

    Object.assign(
        field,
        allowedUpdates
    );


    field.updatedBy =
        userId;


    await field.save();


    return field;

};


// ==========================================================
// DELETE CUSTOM FIELD
// ==========================================================
//
// Soft delete.
//
// RULE:
//
// A custom field can only be deleted if it has NEVER been
// used by a beneficiary.
//
// If at least one beneficiary contains this fieldId,
// deletion is blocked.
//
// This protects historical beneficiary data and prevents
// the field definition from disappearing while beneficiary
// records still reference it.
// ==========================================================

const deleteCustomField = async (
    id,
    organizationId
) => {

    // ======================================================
    // FIND FIELD
    // ======================================================

    const field =
        await CustomField.findOne({

            _id:
                id,

            organization:
                organizationId

        });


    if (!field) {

        throw new Error(
            "Custom field not found"
        );

    }


    // ======================================================
    // CHECK WHETHER FIELD IS USED
    // ======================================================

    const usage =
        await Beneficiary.exists({

            organization:
                organizationId,

            customFields: {

                $elemMatch: {

                    fieldId:
                        field._id

                }

            }

        });


    // ======================================================
    // BLOCK DELETION IF USED
    // ======================================================

    if (usage) {

        throw new Error(

            `Custom field "${field.label}" is already used by beneficiaries and cannot be deleted.`

        );

    }


    // ======================================================
    // SOFT DELETE
    // ======================================================

    field.active =
        false;


    await field.save();


    return field;

};

// ==========================================================
// EXPORT
// ==========================================================

module.exports = {

    createCustomField,

    getCustomFields,

    getCustomFieldById,

    updateCustomField,

    deleteCustomField

};
