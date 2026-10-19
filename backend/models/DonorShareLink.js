const mongoose = require("mongoose");


// =====================================================
// DONOR SHARE LINK
// =====================================================
//
// Private, read-only link that lets a donor see where
// their donations went without an account.
//
// Only a SHA-256 hash of the token is stored; the full
// link is shown once when created. Links expire and
// can be revoked. Beneficiary names follow the donor's
// shareBeneficiaryNames setting at view time.
//
// =====================================================

const shareViewSchema =
    new mongoose.Schema(
        {

            at: {
                type: Date,
                default: Date.now
            },

            userAgent: {
                type: String,
                default: "",
                maxlength: 200
            }

        },
        {
            _id: false
        }
    );


const donorShareLinkSchema =
    new mongoose.Schema(
        {

            organization: {
                type: mongoose.Schema.Types.ObjectId,
                ref: "Organization",
                required: true
            },

            donor: {
                type: mongoose.Schema.Types.ObjectId,
                ref: "Donor",
                required: true
            },

            // null = all of the donor's donations

            donation: {
                type: mongoose.Schema.Types.ObjectId,
                ref: "Donation",
                default: null
            },

            label: {
                type: String,
                default: "",
                trim: true,
                maxlength: 120
            },

            tokenHash: {
                type: String,
                required: true,
                unique: true
            },

            // Last characters of the token, to help staff
            // recognise a link without storing it.

            tokenHint: {
                type: String,
                default: ""
            },

            expiresAt: {
                type: Date,
                required: true
            },

            revokedAt: {
                type: Date,
                default: null
            },

            revokedBy: {
                type: mongoose.Schema.Types.ObjectId,
                ref: "User",
                default: null
            },

            viewCount: {
                type: Number,
                default: 0
            },

            lastViewedAt: {
                type: Date,
                default: null
            },

            // Most recent views only (capped by the service)

            recentViews: {
                type: [shareViewSchema],
                default: []
            },

            createdBy: {
                type: mongoose.Schema.Types.ObjectId,
                ref: "User",
                default: null
            }

        },
        {
            timestamps: true
        }
    );


donorShareLinkSchema.index({
    organization: 1,
    donor: 1,
    createdAt: -1
});


module.exports =
    mongoose.model(
        "DonorShareLink",
        donorShareLinkSchema
    );
