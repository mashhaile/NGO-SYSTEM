const Joi = require("joi");


// =====================================================
// CUSTOM FIELDS
// =====================================================

const customFieldSchema = Joi.object({

    fieldId: Joi.string()
        .pattern(/^[0-9a-fA-F]{24}$/)
        .required()
        .messages({

            "string.pattern.base":
                "Custom field ID must be a valid MongoDB ObjectId."

        }),

    value: Joi.any()
        .allow(null, "")

});


// =====================================================
// DOCUMENTS
// =====================================================

const documentSchema = Joi.object({

    documentType: Joi.string()
        .allow("")
        .optional(),

    fileName: Joi.string()
        .allow("")
        .optional(),

    fileUrl: Joi.string()
        .allow("")
        .optional()

});


// =====================================================
// LOOKUP ID
// =====================================================
//
// All Lookup fields store MongoDB ObjectId values.
//
// Examples:
//
// Gender
// EducationLevel
// Occupation
// MaritalStatus
// DisabilityType
// VulnerableGroup
//
// Display values must be resolved to Lookup IDs
// before this validation is performed.
//
// =====================================================

const lookupId = Joi.string()
    .pattern(/^[0-9a-fA-F]{24}$/)
    .messages({

        "string.pattern.base":
            "Lookup value must be a valid Lookup ID."

    });


// =====================================================
// DATE OF BIRTH
// =====================================================
//
// IMPORTANT:
//
// dateOfBirth is the SOURCE OF TRUTH for age.
//
// Age is NOT accepted from the client.
//
// The beneficiary service calculates:
//
//     age = calculateAge(dateOfBirth)
//
// This applies to:
//
// - Create
// - Update
// - Excel import
// - API requests
//
// =====================================================

const dateOfBirthSchema = Joi.date()
    .max("now")
    .allow(null)
    .optional()
    .messages({

        "date.max":
            "Date of birth cannot be in the future."

    });


// =====================================================
// PWD VALIDATION
// =====================================================
//
// Business rules:
//
// 1. isPWD = true
//    -> disabilityType is required.
//
// 2. isPWD = false
//    -> disabilityType must be empty/null.
//
// The service must also enforce these rules because
// Joi validation alone should not be considered the
// final business/security boundary.
//
// =====================================================

const pwdFields = {

    isPWD: Joi.boolean()
        .default(false),

    disabilityType: lookupId
        .allow(null, "")
        .optional()

};


// =====================================================
// CREATE BENEFICIARY
// =====================================================

const createBeneficiarySchema = Joi.object({

    // =================================================
    // BASIC INFORMATION
    // =================================================

    firstName: Joi.string()
        .trim()
        .min(2)
        .max(50)
        .required(),

    middleName: Joi.string()
        .trim()
        .allow("")
        .optional(),

    lastName: Joi.string()
        .trim()
        .min(2)
        .max(50)
        .required(),


    // =================================================
    // GENDER
    // =================================================

    gender: lookupId
        .required(),


    // =================================================
    // DATE OF BIRTH
    // =================================================
    //
    // Age is intentionally NOT accepted.
    //
    // The backend calculates it automatically.
    //
    // =================================================

    dateOfBirth:
        dateOfBirthSchema,


    // =================================================
    // CONTACT
    // =================================================

    phone: Joi.string()
        .trim()
        .allow("")
        .optional(),

    alternativePhone: Joi.string()
        .trim()
        .allow("")
        .optional(),

    email: Joi.string()
        .email()
        .allow("")
        .optional(),


    // =================================================
    // LOCATION
    // =================================================

    country: Joi.string()
        .allow("")
        .optional(),

    region: Joi.string()
        .allow("")
        .optional(),

    zone: Joi.string()
        .allow("")
        .optional(),

    woreda: Joi.string()
        .allow("")
        .optional(),

    kebele: Joi.string()
        .allow("")
        .optional(),

    address: Joi.string()
        .allow("")
        .optional(),


    // =================================================
    // SOCIO INFORMATION
    // =================================================

    educationLevel: lookupId
        .allow(null, "")
        .optional(),

    occupation: lookupId
        .allow(null, "")
        .optional(),

    maritalStatus: lookupId
        .allow(null, "")
        .optional(),


    // =================================================
    // VULNERABILITY
    // =================================================

    ...pwdFields,

    vulnerableGroups: Joi.array()
        .items(lookupId)
        .default([]),


    // =================================================
    // DOCUMENTS
    // =================================================

    documents: Joi.array()
        .items(documentSchema)
        .default([]),


    // =================================================
    // STATUS
    // =================================================
    //
    // Status is NOT a Lookup.
    //
    // =================================================

    status: Joi.string()
        .valid(
            "Active",
            "Inactive"
        )
        .default("Active"),


    // =================================================
    // CUSTOM FIELDS
    // =================================================

    customFields: Joi.array()
        .items(customFieldSchema)
        .default([])

})
.options({

    // Allows additional fields so the existing
    // controller/service architecture remains compatible.
    //
    // IMPORTANT:
    // The service must still whitelist/protect system fields.
    //
    allowUnknown: true

});


// =====================================================
// UPDATE BENEFICIARY
// =====================================================

const updateBeneficiarySchema = Joi.object({

    // =================================================
    // PROTECTED SYSTEM FIELDS
    // =================================================

    organization: Joi.any()
        .forbidden(),

    beneficiaryNumber: Joi.any()
        .forbidden(),

    createdBy: Joi.any()
        .forbidden(),

    updatedBy: Joi.any()
        .forbidden(),

    isDeleted: Joi.any()
        .forbidden(),

    deletedAt: Joi.any()
        .forbidden(),

    deletedBy: Joi.any()
        .forbidden(),


    // =================================================
    // BASIC INFORMATION
    // =================================================

    firstName: Joi.string()
        .trim()
        .min(2)
        .max(50),

    middleName: Joi.string()
        .trim()
        .allow(""),

    lastName: Joi.string()
        .trim()
        .min(2)
        .max(50),


    // =================================================
    // GENDER
    // =================================================

    gender: lookupId,


    // =================================================
    // DATE OF BIRTH
    // =================================================
    //
    // If dateOfBirth changes, the service recalculates
    // age automatically.
    //
    // The client cannot submit or override age.
    //
    // =================================================

    dateOfBirth:
        Joi.date()
            .max("now")
            .allow(null)
            .messages({

                "date.max":
                    "Date of birth cannot be in the future."

            }),


    // =================================================
    // CONTACT
    // =================================================

    phone: Joi.string()
        .trim()
        .allow(""),

    alternativePhone: Joi.string()
        .trim()
        .allow(""),

    email: Joi.string()
        .email()
        .allow(""),


    // =================================================
    // LOCATION
    // =================================================

    country: Joi.string()
        .allow(""),

    region: Joi.string()
        .allow(""),

    zone: Joi.string()
        .allow(""),

    woreda: Joi.string()
        .allow(""),

    kebele: Joi.string()
        .allow(""),

    address: Joi.string()
        .allow(""),


    // =================================================
    // SOCIO INFORMATION
    // =================================================

    educationLevel: lookupId
        .allow(null, ""),

    occupation: lookupId
        .allow(null, ""),

    maritalStatus: lookupId
        .allow(null, ""),


    // =================================================
    // VULNERABILITY
    // =================================================

    isPWD: Joi.boolean(),

    disabilityType: lookupId
        .allow(null, ""),

    vulnerableGroups: Joi.array()
        .items(lookupId),


    // =================================================
    // DOCUMENTS
    // =================================================

    documents: Joi.array()
        .items(documentSchema),


    // =================================================
    // STATUS
    // =================================================

    status: Joi.string()
        .valid(
            "Active",
            "Inactive"
        ),


    // =================================================
    // CUSTOM FIELDS
    // =================================================

    customFields: Joi.array()
        .items(customFieldSchema)

})
.options({

    // Update uses a strict whitelist.
    allowUnknown: false

})
.min(1);


// =====================================================
// EXPORT
// =====================================================

module.exports = {

    createBeneficiarySchema,

    updateBeneficiarySchema

};
