const mongoose = require("mongoose");


// =====================================================
// ENTERPRISE MEMBER SCHEMA
// =====================================================

const enterpriseMemberSchema = new mongoose.Schema(

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
        // ENTERPRISE
        // =====================================================

        enterprise: {

            type:
                mongoose.Schema.Types.ObjectId,

            ref:
                "Enterprise",

            required:
                true,

            index:
                true

        },


        // =====================================================
        // BENEFICIARY
        // =====================================================

        beneficiary: {

            type:
                mongoose.Schema.Types.ObjectId,

            ref:
                "Beneficiary",

            required:
                true,

            index:
                true

        },


        // =====================================================
        // MEMBER ROLE
        // =====================================================
        //
        // This is NOT a Lookup.
        //
        // Examples:
        // Member
        // Partner
        // Shareholder
        // Manager
        // Employee
        //
        // =====================================================

        memberRole: {

    type: String,

    enum: [
        "Member",
        "Partner",
        "Shareholder",
        "Manager",
        "Employee"
    ],

    default: "Member",

    trim: true

},


        // =====================================================
        // MEMBERSHIP DATES
        // =====================================================

        joinedDate: {

            type:
                Date,

            default:
                null

        },

        leftDate: {

            type:
                Date,

            default:
                null

        },


        // =====================================================
        // MEMBERSHIP STATUS
        // =====================================================
        //
        // NOT a Lookup.
        //
        // =====================================================

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
// PREVENT DUPLICATE ACTIVE RELATIONSHIP
// =====================================================

enterpriseMemberSchema.index(

    {

        organization:
            1,

        enterprise:
            1,

        beneficiary:
            1

    },

    {

        unique:
            true,

        partialFilterExpression: {

            isDeleted:
                false

        }

    }

);


// =====================================================
// ENTERPRISE MEMBERS
// =====================================================

enterpriseMemberSchema.index({

    organization:
        1,

    enterprise:
        1,

    status:
        1,

    isDeleted:
        1

});


// =====================================================
// BENEFICIARY ENTERPRISES
// =====================================================

enterpriseMemberSchema.index({

    organization:
        1,

    beneficiary:
        1,

    status:
        1,

    isDeleted:
        1

});


// =====================================================
// ENTERPRISE + BENEFICIARY
// =====================================================

enterpriseMemberSchema.index({

    organization:
        1,

    enterprise:
        1,

    beneficiary:
        1,

    status:
        1

});


// =====================================================
// REPORTING
// =====================================================

enterpriseMemberSchema.index({

    organization:
        1,

    createdAt:
        -1

});


// =====================================================
// EXPORT
// =====================================================

// dates that must make sense (see plugins/dateRules)
enterpriseMemberSchema.plugin(
    require("./plugins/dateRules"),
    {
        what: "This member",
        labels: { joinedDate: "joining date", leftDate: "leaving date" },
        rules: [
            { order: ["joinedDate", "leftDate"] },
            { inside: { model: "Enterprise", ref: "enterprise", fields: ["joinedDate", "leftDate"], title: "enterprise" } },
            { notFuture: "leftDate" }
        ]
    }
);


// what the status of its parents allows (see plugins/statusRules)
enterpriseMemberSchema.plugin(
    require("./plugins/statusRules"),
    { what: "This member", inactive: [{ ref: "enterprise", model: "Enterprise", label: "enterprise" }, { ref: "beneficiary", model: "Beneficiary", label: "beneficiary" }] }
);


module.exports =
    mongoose.model(

        "EnterpriseMember",

        enterpriseMemberSchema

    );