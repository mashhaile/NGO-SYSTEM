// ==========================================================
// CUSTOM FIELD PROCESSOR
// ==========================================================
//
// Shared processor for ALL modules.
//
// Examples:
// - Beneficiary
// - Enterprise
// - EnterpriseMember
// - Donor
// - Program
// - ServiceDelivery
// - User
// - Future modules
//
// createMode = true
//     Only ACTIVE custom fields can be submitted.
//
// createMode = false
//     Existing inactive custom fields are allowed so
//     historical data is not destroyed.
//
// ==========================================================

const mongoose = require("mongoose");

const CustomField =
    require("../models/CustomField");


// ==========================================================
// PROCESS CUSTOM FIELDS
// ==========================================================

const processCustomFields = async (
    customFields = [],
    organizationId,
    createMode = false,
    module = "Beneficiary"
) => {

    // ======================================================
    // BASIC INPUT
    // ======================================================

    if (!Array.isArray(customFields)) {
        return [];
    }


    if (customFields.length === 0) {
        return [];
    }


    // ======================================================
    // ORGANIZATION
    // ======================================================

    if (!organizationId) {

        throw new Error(
            "Organization is required for custom fields"
        );

    }


    // ======================================================
    // MODULE
    // ======================================================

    if (
        !module ||
        typeof module !== "string"
    ) {

        throw new Error(
            "Custom field module is required"
        );

    }


    module =
        module.trim();


    // ======================================================
    // BASIC STRUCTURE VALIDATION
    // ======================================================

    if (
        customFields.some(
            item =>
                !item ||
                !item.fieldId
        )
    ) {

        throw new Error(
            "Invalid custom field data"
        );

    }


    // ======================================================
    // VALIDATE FIELD IDS
    // ======================================================

    const fieldIds =
        customFields.map(
            item =>
                String(item.fieldId)
        );


    // ------------------------------------------------------
    // CHECK OBJECTIDS
    // ------------------------------------------------------

    const invalidFieldId =
        fieldIds.find(
            id =>
                !mongoose.Types.ObjectId.isValid(id)
        );


    if (invalidFieldId) {

        throw new Error(
            `Invalid custom field ID: ${invalidFieldId}`
        );

    }


    // ======================================================
    // PREVENT DUPLICATES
    // ======================================================

    const uniqueFieldIds =
        new Set(fieldIds);


    if (
        uniqueFieldIds.size !==
        fieldIds.length
    ) {

        throw new Error(
            "Duplicate custom fields are not allowed"
        );

    }


    // ======================================================
    // LOAD CUSTOM FIELD DEFINITIONS
    // ======================================================

    const fieldQuery = {

        _id: {
            $in: fieldIds
        },

        organization:
            organizationId,

        module:
            module

    };


    // ======================================================
    // CREATE MODE
    // ======================================================
    //
    // New records may only use active fields.
    //

    if (createMode) {

        fieldQuery.active = true;

    }


    const fields =
        await CustomField.find(
            fieldQuery
        );


    // ======================================================
    // VERIFY ALL FIELDS
    // ======================================================

    if (
        fields.length !==
        uniqueFieldIds.size
    ) {

        throw new Error(

            createMode

                ? `One or more custom fields are invalid, inactive, or do not belong to the ${module} module`

                : `One or more custom fields are invalid or do not belong to the ${module} module`

        );

    }


    // ======================================================
    // FIELD MAP
    // ======================================================

    const fieldMap =
        new Map(

            fields.map(
                field => [

                    field._id.toString(),

                    field

                ]
            )

        );


    // ======================================================
    // PROCESS FIELDS
    // ======================================================

    const processedFields =
        customFields.map(
            item => {

                const field =
                    fieldMap.get(
                        String(item.fieldId)
                    );


                if (!field) {

                    throw new Error(
                        "Invalid custom field"
                    );

                }


                let value =
                    item.value;


                // ==================================================
                // EMPTY VALUE
                // ==================================================

                const isEmpty =

                    value === undefined ||

                    value === null ||

                    value === "" ||

                    (
                        Array.isArray(value) &&
                        value.length === 0
                    );


                // ==================================================
                // REQUIRED
                // ==================================================

                if (
                    field.required &&
                    isEmpty
                ) {

                    throw new Error(
                        `${field.label} is required`
                    );

                }


                // ==================================================
                // OPTIONAL EMPTY
                // ==================================================

                if (isEmpty) {

                    return {

                        fieldId:
                            field._id,

                        value:
                            null

                    };

                }


                // ==================================================
                // TEXT
                // ==================================================

                if (
                    [
                        "text",
                        "email",
                        "phone",
                        "textarea",
                        "location"
                    ].includes(field.type)
                ) {

                    if (
                        typeof value !== "string"
                    ) {

                        throw new Error(
                            `${field.label} must be text`
                        );

                    }


                    value =
                        value.trim();


                    // ----------------------------------------------
                    // MIN LENGTH
                    // ----------------------------------------------

                    if (
                        field.validation?.minLength !==
                        null &&

                        field.validation?.minLength !==
                        undefined &&

                        value.length <
                        field.validation.minLength
                    ) {

                        throw new Error(
                            `${field.label} must be at least ${field.validation.minLength} characters`
                        );

                    }


                    // ----------------------------------------------
                    // MAX LENGTH
                    // ----------------------------------------------

                    if (
                        field.validation?.maxLength !==
                        null &&

                        field.validation?.maxLength !==
                        undefined &&

                        value.length >
                        field.validation.maxLength
                    ) {

                        throw new Error(
                            `${field.label} must not exceed ${field.validation.maxLength} characters`
                        );

                    }


                    // ----------------------------------------------
                    // PATTERN
                    // ----------------------------------------------

                    if (
                        field.validation?.pattern
                    ) {

                        let regex;

                        try {

                            regex =
                                new RegExp(
                                    field.validation.pattern
                                );

                        }
                        catch (error) {

                            throw new Error(
                                `Invalid validation pattern configured for ${field.label}`
                            );

                        }


                        if (
                            !regex.test(value)
                        ) {

                            throw new Error(
                                `${field.label} has an invalid format`
                            );

                        }

                    }


                    // ----------------------------------------------
                    // EMAIL
                    // ----------------------------------------------

                    if (
                        field.type === "email"
                    ) {

                        const emailRegex =
                            /^[^\s@]+@[^\s@]+\.[^\s@]+$/;


                        if (
                            !emailRegex.test(value)
                        ) {

                            throw new Error(
                                `${field.label} must be a valid email address`
                            );

                        }

                    }

                }


                // ==================================================
                // NUMBER / CURRENCY
                // ==================================================

                if (
                    [
                        "number",
                        "currency"
                    ].includes(field.type)
                ) {

                    const numericValue =
                        Number(value);


                    if (
                        value === "" ||
                        !Number.isFinite(
                            numericValue
                        )
                    ) {

                        throw new Error(
                            `${field.label} must be a valid number`
                        );

                    }


                    // ----------------------------------------------
                    // MIN
                    // ----------------------------------------------

                    if (
                        field.validation?.minValue !==
                        null &&

                        field.validation?.minValue !==
                        undefined &&

                        numericValue <
                        field.validation.minValue
                    ) {

                        throw new Error(
                            `${field.label} must be at least ${field.validation.minValue}`
                        );

                    }


                    // ----------------------------------------------
                    // MAX
                    // ----------------------------------------------

                    if (
                        field.validation?.maxValue !==
                        null &&

                        field.validation?.maxValue !==
                        undefined &&

                        numericValue >
                        field.validation.maxValue
                    ) {

                        throw new Error(
                            `${field.label} must not exceed ${field.validation.maxValue}`
                        );

                    }


                    value =
                        numericValue;

                }


                // ==================================================
                // DATE
                // ==================================================

                if (
                    field.type === "date"
                ) {

                    if (
                        typeof value !== "string" &&
                        !(value instanceof Date)
                    ) {

                        throw new Error(
                            `${field.label} must be a valid date`
                        );

                    }


                    const date =
                        new Date(value);


                    if (
                        Number.isNaN(
                            date.getTime()
                        )
                    ) {

                        throw new Error(
                            `${field.label} must be a valid date`
                        );

                    }


                    value =
                        date;

                }


                // ==================================================
                // SELECT / RADIO
                // ==================================================

                if (
                    [
                        "select",
                        "radio"
                    ].includes(field.type)
                ) {

                    const allowedValues =

                        Array.isArray(field.options)

                            ? field.options.map(
                                option =>
                                    String(
                                        option.value
                                    )
                            )

                            : [];


                    const normalizedValue =
                        String(value);


                    if (
                        !allowedValues.includes(
                            normalizedValue
                        )
                    ) {

                        throw new Error(
                            `${field.label} contains an invalid option`
                        );

                    }


                    value =
                        normalizedValue;

                }


                // ==================================================
                // MULTI SELECT
                // ==================================================

                if (
                    field.type === "multi_select"
                ) {

                    if (
                        !Array.isArray(value)
                    ) {

                        throw new Error(
                            `${field.label} must contain multiple selected values`
                        );

                    }


                    const allowedValues =

                        Array.isArray(field.options)

                            ? field.options.map(
                                option =>
                                    String(
                                        option.value
                                    )
                            )

                            : [];


                    const normalizedValues =
                        value.map(
                            item =>
                                String(item)
                        );


                    const invalidValues =
                        normalizedValues.filter(
                            item =>
                                !allowedValues.includes(
                                    item
                                )
                        );


                    if (
                        invalidValues.length > 0
                    ) {

                        throw new Error(
                            `${field.label} contains one or more invalid options`
                        );

                    }


                    value =
                        [
                            ...new Set(
                                normalizedValues
                            )
                        ];

                }


                // ==================================================
                // CHECKBOX
                // ==================================================

                if (
                    field.type === "checkbox"
                ) {

                    if (
                        typeof value !== "boolean"
                    ) {

                        if (
                            value === "true"
                        ) {

                            value = true;

                        }

                        else if (
                            value === "false"
                        ) {

                            value = false;

                        }

                        else {

                            throw new Error(
                                `${field.label} must be true or false`
                            );

                        }

                    }

                }


                // ==================================================
                // FILE
                // ==================================================

                if (
                    field.type === "file"
                ) {

                    // File handling can be added
                    // through the storage layer.

                }


                // ==================================================
                // RETURN
                // ==================================================

                return {

                    fieldId:
                        field._id,

                    value

                };

            }
        );


    // ======================================================
    // RETURN
    // ======================================================

    return processedFields;

};


// ==========================================================
// EXPORT
// ==========================================================

module.exports = {

    processCustomFields

};