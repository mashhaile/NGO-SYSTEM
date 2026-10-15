const mongoose = require("mongoose");


// =====================================================
// BENEFICIARY SCHEMA
// =====================================================

const beneficiarySchema = new mongoose.Schema(
    {

        // =================================================
        // ORGANIZATION
        // =================================================

        organization: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Organization",
            required: true,
            index: true
        },


        // =================================================
        // BENEFICIARY NUMBER
        // =================================================

        beneficiaryNumber: {
            type: String,
            required: true,
            trim: true
        },


        // =================================================
        // BASIC INFORMATION
        // =================================================

        firstName: {
            type: String,
            required: true,
            trim: true
        },

        middleName: {
            type: String,
            default: "",
            trim: true
        },

        lastName: {
            type: String,
            required: true,
            trim: true
        },


        // =================================================
        // GENDER
        // =================================================
        //
        // Lookup Management:
        //
        // Module:
        // Beneficiary
        //
        // Category:
        // Gender
        //
        // Only the Lookup ObjectId is stored here.
        //
        // The actual value/category/code remain in Lookup.
        // =================================================

        gender: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Lookup",
            default: null
        },


        // =================================================
        // DATE / AGE
        // =================================================

        dateOfBirth: {
            type: Date,
            default: null
        },

        age: {
            type: Number,
            default: null
        },


        // =================================================
        // CONTACT INFORMATION
        // =================================================

        phone: {
            type: String,
            default: "",
            trim: true
        },

        alternativePhone: {
            type: String,
            default: "",
            trim: true
        },

        email: {
            type: String,
            default: "",
            lowercase: true,
            trim: true
        },


        // =================================================
        // LOCATION
        // =================================================

        country: {
            type: String,
            default: "",
            trim: true
        },

        region: {
            type: String,
            default: "",
            trim: true
        },

        zone: {
            type: String,
            default: "",
            trim: true
        },

        woreda: {
            type: String,
            default: "",
            trim: true
        },

        kebele: {
            type: String,
            default: "",
            trim: true
        },

        address: {
            type: String,
            default: "",
            trim: true
        },


        // =================================================
        // SOCIO INFORMATION
        // =================================================

        // Lookup:
        // Beneficiary / EducationLevel

        educationLevel: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Lookup",
            default: null
        },


        // Lookup:
        // Beneficiary / Occupation

        occupation: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Lookup",
            default: null
        },


        // Lookup:
        // Beneficiary / MaritalStatus

        maritalStatus: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Lookup",
            default: null
        },


        // =================================================
        // VULNERABILITY INFORMATION
        // =================================================

        // =================================================
        // PERSON WITH DISABILITY
        // =================================================
        //
        // This is a system Boolean.
        //
        // It is NOT a Lookup.
        // =================================================

        isPWD: {
            type: Boolean,
            default: false
        },


        // =================================================
        // DISABILITY TYPE
        // =================================================
        //
        // Lookup:
        // Beneficiary / DisabilityType
        //
        // Business validation belongs in the service layer:
        //
        // isPWD === true
        //      ↓
        // disabilityType may be required
        //
        // =================================================

        disabilityType: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Lookup",
            default: null
        },


        // =================================================
        // VULNERABLE GROUPS
        // =================================================
        //
        // Lookup:
        // Beneficiary / VulnerableGroup
        //
        // Multiple values are allowed.
        // =================================================

        vulnerableGroups: [
            {
                type: mongoose.Schema.Types.ObjectId,
                ref: "Lookup"
            }
        ],


        // =================================================
        // DOCUMENTS
        // =================================================

        documents: [
            {

                documentType: {
                    type: String,
                    default: "",
                    trim: true
                },

                fileName: {
                    type: String,
                    default: "",
                    trim: true
                },

                fileUrl: {
                    type: String,
                    default: "",
                    trim: true
                },

                uploadedAt: {
                    type: Date,
                    default: Date.now
                }

            }
        ],


        // =================================================
        // STATUS
        // =================================================
        //
        // System-controlled.
        // NOT a Lookup.
        // =================================================

        status: {
            type: String,
            enum: [
                "Active",
                "Inactive"
            ],
            default: "Active"
        },


        // =================================================
        // CUSTOM FIELDS
        // =================================================
        //
        // CustomField remains separate from Lookup Management.
        //
        // Lookup Management does NOT depend on this.
        //
        // CustomField is simply another configurable
        // Beneficiary feature.
        // =================================================

        customFields: [
            {

                fieldId: {
                    type: mongoose.Schema.Types.ObjectId,
                    ref: "CustomField",
                    required: true
                },

                value: {
                    type: mongoose.Schema.Types.Mixed,
                    default: null
                }

            }
        ],


        // =================================================
        // AUDIT
        // =================================================

        createdBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            default: null
        },

        updatedBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            default: null
        },


        // =================================================
        // SOFT DELETE
        // =================================================

        isDeleted: {
            type: Boolean,
            default: false
        },

        deletedAt: {
            type: Date,
            default: null
        },

        deletedBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            default: null
        }

    },

    {
        timestamps: true
    }
);


// =====================================================
// INDEXES
// =====================================================

// -----------------------------------------------------
// Prevent duplicate beneficiary number
// inside the same organization.
// -----------------------------------------------------

beneficiarySchema.index(
    {
        organization: 1,
        beneficiaryNumber: 1
    },
    {
        unique: true
    }
);


// -----------------------------------------------------
// Search optimization.
// -----------------------------------------------------

beneficiarySchema.index({
    organization: 1,
    firstName: 1,
    lastName: 1,
    phone: 1
});


// -----------------------------------------------------
// Lookup-based filtering.
// -----------------------------------------------------

beneficiarySchema.index({
    organization: 1,
    gender: 1
});

beneficiarySchema.index({
    organization: 1,
    educationLevel: 1
});

beneficiarySchema.index({
    organization: 1,
    occupation: 1
});

beneficiarySchema.index({
    organization: 1,
    maritalStatus: 1
});

beneficiarySchema.index({
    organization: 1,
    disabilityType: 1
});

beneficiarySchema.index({
    organization: 1,
    vulnerableGroups: 1
});


// -----------------------------------------------------
// Active beneficiary filtering.
// -----------------------------------------------------

beneficiarySchema.index({
    organization: 1,
    isDeleted: 1,
    status: 1
});


// =====================================================
// MODEL
// =====================================================

module.exports = mongoose.model(
    "Beneficiary",
    beneficiarySchema
);