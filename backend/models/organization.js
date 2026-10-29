const mongoose = require("mongoose");

const {
    ORGANIZATION_STATUS
} = require("../config/constants");


// =====================================================
// ORGANIZATION SCHEMA
// =====================================================
//
// IMPORTANT:
//
// Organization stores organization identity, lifecycle,
// contact, branding, trial metadata and platform metadata.
//
// Subscription/Plan is responsible for:
// - subscription status
// - billing
// - plan features
// - resource limits
// - module access
//
// ALL APPLICATION MODULES ARE AVAILABLE TO ALL PLANS.
//
// DO NOT STORE enabledModules HERE.
// =====================================================

const organizationSchema = new mongoose.Schema(

    {

        // =================================================
        // ORGANIZATION IDENTITY
        // =================================================

        organizationCode: {

            type: String,

            unique: true,

            required: [
                true,
                "Organization code is required"
            ],

            uppercase: true,

            trim: true

        },


        name: {

            type: String,

            required: [
                true,
                "Organization name is required"
            ],

            trim: true,

            minlength: 3,

            maxlength: 100

        },


        legalName: {

            type: String,

            trim: true,

            maxlength: 150

        },


        organizationType: {

            type: String,

            trim: true,

            maxlength: 100

        },


        description: {

            type: String,

            trim: true,

            maxlength: 1000

        },


        foundedYear: {

            type: Number,

            min: 1800,

            max: new Date().getFullYear()

        },


        // =================================================
        // REGISTRATION / LEGAL INFORMATION
        // =================================================

        registrationNumber: {

            type: String,

            trim: true,

            maxlength: 100

        },


        taxIdentificationNumber: {

            type: String,

            trim: true,

            maxlength: 100

        },


        // =================================================
        // PRIMARY CONTACT INFORMATION
        // =================================================

        email: {

            type: String,

            required: [
                true,
                "Organization email is required"
            ],

            unique: true,

            lowercase: true,

            trim: true

        },


        phone: {

            type: String,

            required: [
                true,
                "Phone number is required"
            ],

            trim: true

        },


        alternativePhone: {

            type: String,

            trim: true

        },


        website: {

            type: String,

            trim: true

        },


        // =================================================
        // PRIMARY ORGANIZATION CONTACT PERSON
        // =================================================

        primaryContact: {

            name: {

                type: String,

                trim: true,

                maxlength: 100

            },


            position: {

                type: String,

                trim: true,

                maxlength: 100

            },


            email: {

                type: String,

                lowercase: true,

                trim: true

            },


            phone: {

                type: String,

                trim: true

            }

        },


        // =================================================
        // ORGANIZATION ADDRESS
        // =================================================

        address: {

            type: String,

            trim: true,

            maxlength: 250

        },


        addressLine2: {

            type: String,

            trim: true,

            maxlength: 250

        },


        city: {

            type: String,

            trim: true,

            maxlength: 100

        },


        stateRegion: {

            type: String,

            trim: true,

            maxlength: 100

        },


        postalCode: {

            type: String,

            trim: true,

            maxlength: 30

        },


        country: {

            type: String,

            required: [
                true,
                "Country is required"
            ],

            trim: true,

            maxlength: 100

        },


        // =================================================
        // THE ORGANIZATION'S OWN WORDS
        // { donation: { singular: "Fund", plural: "Funds" } }
        // (see config/terminology.js)
        // =================================================

        terminology: {

            type: mongoose.Schema.Types.Mixed,

            default: {}

        },

        // =================================================
        // MODULES SWITCHED ON / OFF BY THE PLATFORM ADMIN
        // { tor: false, funding: true } (missing: the
        // module's default; see config/modules.js)
        // =================================================

        modules: {

            type: mongoose.Schema.Types.Mixed,

            default: {}

        },

        // =================================================
        // M&E: WHEN AN INDICATOR IS ON TRACK / AT RISK
        // { onTrack: 90, atRisk: 60 } (% achieved; empty:
        // the defaults, see services/indicatorService.js)
        // =================================================

        meSettings: {

            type: mongoose.Schema.Types.Mixed,

            default: {}

        },

        // =================================================
        // PROCUREMENT: METHODS BY AMOUNT
        // { methods: { direct: { upTo, minQuotes, committee },
        // rfq: {...}, tender: {...} } } (empty: the defaults,
        // see services/procurementSettingsService.js)
        // =================================================

        procurementSettings: {

            type: mongoose.Schema.Types.Mixed,

            default: {}

        },

        // =================================================
        // HUMANITARIAN RESPONSE: DUPLICATE CHECK
        // { duplicateCheck: { enabled, period, days, sameProject } }
        // (empty: the defaults, see services/humanitarianService.js)
        // =================================================

        humanitarianSettings: {

            type: mongoose.Schema.Types.Mixed,

            default: {}

        },

        // =================================================
        // ORGANIZATION BRANDING
        // =================================================

        logo: {

            type: String,

            default: "",

            trim: true

        },


        // =================================================
        // ORGANIZATION LIFECYCLE
        // =================================================
        //
        // IMPORTANT:
        //
        // This is NOT subscription status.
        //
        // Organization lifecycle:
        //
        // trial
        // active
        // suspended
        // inactive
        //
        // Subscription status remains in Subscription.
        // =================================================

        status: {

            type: String,

            enum: Object.values(
                ORGANIZATION_STATUS
            ),

            default:
                ORGANIZATION_STATUS.TRIAL,

            index: true

        },


        activatedAt: {

            type: Date,

            default: null

        },


        suspendedAt: {

            type: Date,

            default: null

        },


        suspensionReason: {

            type: String,

            trim: true,

            maxlength: 500,

            default: ""

        },


        // =================================================
        // TRIAL INFORMATION
        // =================================================
        //
        // These fields are organization lifecycle metadata.
        //
        // Subscription remains the source of truth for:
        // - plan
        // - billing
        // - subscription period
        // - subscription status
        // =================================================

        trialStartedAt: {

            type: Date,

            default: null

        },


        trialEndedAt: {

            type: Date,

            default: null

        },


        // =================================================
        // SOFT DELETE
        // =================================================
        //
        // Organizations are never physically removed.
        // =================================================

        isDeleted: {

            type: Boolean,

            default: false,

            index: true

        },


        deletedAt: {

            type: Date,

            default: null

        },


        // =================================================
        // PLATFORM METADATA
        // =================================================

        createdBy: {

            type:
                mongoose.Schema.Types.ObjectId,

            ref: "User",

            default: null

        },


        updatedBy: {

            type:
                mongoose.Schema.Types.ObjectId,

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
//
// organizationCode and email already have unique indexes
// from their field definitions.
//
// status and isDeleted are indexed above.
//
// createdAt is indexed below for organization listings.
// =====================================================

organizationSchema.index({

    createdAt: -1

});


// =====================================================
// EXPORT
// =====================================================

module.exports = mongoose.model(

    "Organization",

    organizationSchema

);