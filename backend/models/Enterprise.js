const mongoose = require("mongoose");


// =====================================================
// ENTERPRISE SCHEMA
// =====================================================

const enterpriseSchema = new mongoose.Schema(

    {

        // =====================================================
        // TENANT ISOLATION
        // =====================================================

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


        // =====================================================
        // ENTERPRISE IDENTIFICATION
        // =====================================================

        enterpriseNumber: {

            type:
                String,

            required:
                true,

            trim:
                true

        },

        name: {

            type:
                String,

            required:
                true,

            trim:
                true

        },

        description: {

            type:
                String,

            default:
                null,

            trim:
                true

        },


        // =====================================================
        // LOOKUP FIELDS
        // =====================================================
        //
        // These are controlled by systemLookupFields.js:
        //
        // EnterpriseType
        // OwnershipType
        // BusinessSector
        //
        // They store Lookup ObjectIds.
        // =====================================================

        enterpriseType: {

            type:
                mongoose.Schema.Types.ObjectId,

            ref:
                "Lookup",

            default:
                null

        },

        ownershipType: {

            type:
                mongoose.Schema.Types.ObjectId,

            ref:
                "Lookup",

            default:
                null

        },

        businessSector: {

            type:
                mongoose.Schema.Types.ObjectId,

            ref:
                "Lookup",

            default:
                null

        },


        // =====================================================
        // STATUS
        // =====================================================
        //
        // STATUS IS NOT A LOOKUP.
        //
        // It is a normal system field.
        //
        // Example:
        //
        // "Active"
        // "Inactive"
        // "Suspended"
        //
        // Therefore DO NOT use ObjectId here.
        // =====================================================

        status: {

            type:
                String,

            default:
                null,

            trim:
                true

        },


        // =====================================================
        // DATES
        // =====================================================

        startDate: {

            type:
                Date,

            default:
                null

        },

        endDate: {

            type:
                Date,

            default:
                null

        },


        // =====================================================
        // LOCATION
        // =====================================================

        country: {

            type:
                String,

            default:
                null,

            trim:
                true

        },

        region: {

            type:
                String,

            default:
                null,

            trim:
                true

        },

        zone: {

            type:
                String,

            default:
                null,

            trim:
                true

        },

        woreda: {

            type:
                String,

            default:
                null,

            trim:
                true

        },

        kebele: {

            type:
                String,

            default:
                null,

            trim:
                true

        },

        address: {

            type:
                String,

            default:
                null,

            trim:
                true

        },


        // =====================================================
        // CONTACT
        // =====================================================

        phone: {

            type:
                String,

            default:
                null,

            trim:
                true

        },

        email: {

            type:
                String,

            default:
                null,

            trim:
                true,

            lowercase:
                true

        },


        // =====================================================
        // CUSTOM FIELDS
        // =====================================================

        customFields: [

            {

                fieldId: {

                    type:
                        mongoose.Schema.Types.ObjectId,

                    ref:
                        "CustomField",

                    required:
                        true

                },

                value: {

                    type:
                        mongoose.Schema.Types.Mixed,

                    default:
                        null

                }

            }

        ],


        // =====================================================
        // AUDIT
        // =====================================================

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

        },


        // =====================================================
        // SOFT DELETE
        // =====================================================

        isDeleted: {

            type:
                Boolean,

            default:
                false,

            index:
                true

        },

        deletedAt: {

            type:
                Date,

            default:
                null

        },

        deletedBy: {

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
// VALIDATE ENTERPRISE DATES
// =====================================================

enterpriseSchema.pre(

    "validate",

    async function () {

        if (

            this.startDate &&

            this.endDate &&

            this.endDate < this.startDate

        ) {

            throw new Error(

                "End date cannot be before start date"

            );

        }

    }

);


// =====================================================
// UNIQUE ENTERPRISE NUMBER PER ORGANIZATION
// =====================================================

enterpriseSchema.index(

    {

        organization:
            1,

        enterpriseNumber:
            1

    },

    {

        unique:
            true

    }

);


// =====================================================
// ORGANIZATION + STATUS
// =====================================================

enterpriseSchema.index({

    organization:
        1,

    status:
        1,

    isDeleted:
        1

});


// =====================================================
// ORGANIZATION + NAME
// =====================================================

enterpriseSchema.index({

    organization:
        1,

    name:
        1

});


// =====================================================
// ORGANIZATION + ENTERPRISE TYPE
// =====================================================

enterpriseSchema.index({

    organization:
        1,

    enterpriseType:
        1,

    isDeleted:
        1

});


// =====================================================
// ORGANIZATION + BUSINESS SECTOR
// =====================================================

enterpriseSchema.index({

    organization:
        1,

    businessSector:
        1,

    isDeleted:
        1

});


// =====================================================
// ORGANIZATION + OWNERSHIP TYPE
// =====================================================

enterpriseSchema.index({

    organization:
        1,

    ownershipType:
        1,

    isDeleted:
        1

});


// =====================================================
// EXPORT
// =====================================================

module.exports = mongoose.model(

    "Enterprise",

    enterpriseSchema

);