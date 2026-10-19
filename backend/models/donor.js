const mongoose = require("mongoose");



const donorSchema = new mongoose.Schema(

    {

        // =====================================
        // Tenant Isolation
        // =====================================

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



        // =====================================
        // Donor Identity
        // =====================================

        name: {

            type:
                String,

            required:
                true,

            trim:
                true

        },


        donorType: {

            type:
                String,

            enum: [

                "Individual",
                "Organization",
                "Government",
                "NGO",
                "Corporate",
                "Foundation"

            ],

            default:
                "Organization",

            index:
                true

        },


        country: {

            type:
                String,

            trim:
                true,

            default:
                null,

            index:
                true

        },


        website: {

            type:
                String,

            trim:
                true,

            default:
                null

        },


        registrationNumber: {

            type:
                String,

            trim:
                true,

            default:
                null

        },



        // =====================================
        // Relationship Management
        // =====================================

        donorSince: {

            type:
                Date,

            default:
                Date.now

        },


        lastContactDate: {

            type:
                Date,

            default:
                null

        },


        nextFollowUpDate: {

            type:
                Date,

            default:
                null

        },



        // =====================================
        // Contact Information
        // =====================================

        email: {

            type:
                String,

            trim:
                true,

            lowercase:
                true,

            match:
                /^\S+@\S+\.\S+$/,

            default:
                null

        },


        phone: {

            type:
                String,

            trim:
                true,

            default:
                null

        },


        address: {

            type:
                String,

            default:
                null

        },


        contactPerson: {

            type:
                String,

            default:
                null

        },



        // =====================================
        // Status
        // =====================================

        status: {

            type:
                String,

            enum: [

                "Active",
                "Inactive"

            ],

            default:
                "Active",

            index:
                true

        },


        notes: {

            type:
                String,

            default:
                null

        },


        // Donation trace: include beneficiary names in
        // statements / share links for this donor.
        // Off by default (aggregated numbers only).

        shareBeneficiaryNames: {

            type:
                Boolean,

            default:
                false

        },



        // =====================================
        // Audit
        // =====================================

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



        // =====================================
        // Soft Delete
        // =====================================

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



// =====================================
// UNIQUE DONOR
// =====================================

donorSchema.index(

    {

        organization:
            1,

        name:
            1,

        donorType:
            1

    },

    {

        unique:
            true

    }

);



// =====================================
// REPORTING INDEXES
// =====================================

donorSchema.index({

    organization:
        1,

    donorType:
        1

});


donorSchema.index({

    organization:
        1,

    status:
        1

});


donorSchema.index({

    organization:
        1,

    country:
        1

});



// =====================================
// FOLLOW-UP INDEX
// =====================================

donorSchema.index({

    organization:
        1,

    nextFollowUpDate:
        1

});



module.exports =
    mongoose.model(
        "Donor",
        donorSchema
    );
