const mongoose = require("mongoose");

const {
    SUBSCRIPTION_STATUS,
    BILLING_CYCLES
} = require("../config/constants");


// =====================================================
// SUBSCRIPTION SCHEMA
// =====================================================

const subscriptionSchema = new mongoose.Schema(

    {

        // =================================================
        // ORGANIZATION
        // =================================================

        organization: {

            type: mongoose.Schema.Types.ObjectId,

            ref: "Organization",

            required: true

        },


        // =================================================
        // PLAN
        // =================================================

        plan: {

            type: mongoose.Schema.Types.ObjectId,

            ref: "Plan",

            required: true

        },


        // =================================================
        // STATUS
        // =================================================

        status: {

            type: String,

            enum: Object.values(
                SUBSCRIPTION_STATUS
            ),

            required: true,

            default:
                SUBSCRIPTION_STATUS.ACTIVE,

            index: true

        },


        // =================================================
        // SUBSCRIPTION PERIOD
        // =================================================

        startDate: {

            type: Date,

            required: true,

            default: Date.now

        },


        endDate: {

            type: Date,

            default: null

        },


        // =================================================
        // TRIAL
        // =================================================

        trialStartDate: {

            type: Date,

            default: null

        },


        trialEndDate: {

            type: Date,

            default: null

        },


        // =================================================
        // AUTO RENEW
        // =================================================

        autoRenew: {

            type: Boolean,

            default: false

        },


        // =================================================
        // CANCELLATION
        // =================================================

        cancelAtPeriodEnd: {

            type: Boolean,

            default: false

        },


        cancelledAt: {

            type: Date,

            default: null

        },


        cancellationReason: {

            type: String,

            default: "",

            trim: true,

            maxlength: 500

        },


        // =================================================
        // PLAN SNAPSHOT
        // =================================================
        //
        // Stores the commercial configuration of the plan
        // at the time the subscription is created/changed.
        //
        // moduleAccess is intentionally NOT stored here.
        //
        // All organizations have access to all modules.
        // Limits control quantities.
        // Features control optional functionality.
        //
        // =================================================

        planSnapshot: {

            // ---------------------------------------------
            // PLAN IDENTITY
            // ---------------------------------------------

            name: {

                type: String,

                required: true,

                trim: true,

                maxlength: 100

            },


            code: {

                type: String,

                required: true,

                uppercase: true,

                trim: true,

                maxlength: 50

            },


            // ---------------------------------------------
            // PRICING
            // ---------------------------------------------

            price: {

                type: Number,

                required: true,

                min: 0

            },


            currency: {

                type: String,

                required: true,

                uppercase: true,

                trim: true,

                minlength: 3,

                maxlength: 3,

                match: /^[A-Z]{3}$/

            },


            // ---------------------------------------------
            // BILLING
            // ---------------------------------------------

            billingCycle: {

                type: String,

                enum: Object.values(
                    BILLING_CYCLES
                ),

                required: true

            },


            // ---------------------------------------------
            // FEATURES
            // ---------------------------------------------

            features: {

                type: mongoose.Schema.Types.Mixed,

                required: true,

                default: () => ({})

            },


            // ---------------------------------------------
            // LIMITS
            // ---------------------------------------------

            limits: {

                type: mongoose.Schema.Types.Mixed,

                required: true,

                default: () => ({})

            },


            // ---------------------------------------------
            // TRIAL
            // ---------------------------------------------

            trialDays: {

                type: Number,

                default: 0,

                min: 0,

                max: 365

            }

        },


        // =================================================
        // CREATED BY
        // =================================================

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


// =====================================================
// INDEXES
// =====================================================

// Organization + status lookup

subscriptionSchema.index({

    organization: 1,

    status: 1

});


// =====================================================
// ONE CURRENT SUBSCRIPTION PER ORGANIZATION
// =====================================================
//
// An organization may have many historical subscriptions,
// but only one ACTIVE or TRIALING subscription.
//
// EXPIRED and CANCELLED subscriptions remain available
// for history and audit purposes.
//
// =====================================================

subscriptionSchema.index(

    {

        organization: 1

    },

    {

        unique: true,

        partialFilterExpression: {

            status: {

                $in: [

                    SUBSCRIPTION_STATUS.ACTIVE,

                    SUBSCRIPTION_STATUS.TRIALING

                ]

            }

        }

    }

);


// =====================================================
// VALIDATION
// =====================================================
//
// IMPORTANT:
// Use async middleware here.
//
// Do NOT use function(next).
// Do NOT call next().
//
// =====================================================

subscriptionSchema.pre(

    "validate",

    async function() {

        // =================================================
        // PLAN SNAPSHOT
        // =================================================

        if (!this.planSnapshot) {

            throw new Error(
                "Subscription plan snapshot is required."
            );

        }


        // =================================================
        // PLAN SNAPSHOT CODE
        // =================================================

        if (

            typeof this.planSnapshot.code !==
                "string" ||

            !this.planSnapshot.code.trim()

        ) {

            throw new Error(
                "Subscription plan snapshot code is required."
            );

        }


        this.planSnapshot.code =
            this.planSnapshot.code
                .trim()
                .toUpperCase();


        // =================================================
        // PLAN SNAPSHOT CURRENCY
        // =================================================

        if (

            typeof this.planSnapshot.currency !==
                "string" ||

            !/^[A-Za-z]{3}$/.test(

                this.planSnapshot.currency.trim()

            )

        ) {

            throw new Error(
                "Subscription plan snapshot currency is invalid."
            );

        }


        this.planSnapshot.currency =
            this.planSnapshot.currency
                .trim()
                .toUpperCase();


        // =================================================
        // PLAN SNAPSHOT PRICE
        // =================================================

        const price =
            Number(
                this.planSnapshot.price
            );


        if (

            !Number.isFinite(price) ||

            price < 0

        ) {

            throw new Error(
                "Subscription plan snapshot price is invalid."
            );

        }


        this.planSnapshot.price =
            price;


        // =================================================
        // PLAN SNAPSHOT BILLING CYCLE
        // =================================================

        if (

            !Object.values(
                BILLING_CYCLES
            ).includes(

                this.planSnapshot.billingCycle

            )

        ) {

            throw new Error(
                "Subscription plan snapshot billing cycle is invalid."
            );

        }


        // =================================================
        // TRIAL DAYS
        // =================================================

        const trialDays =
            Number(
                this.planSnapshot.trialDays
            );


        if (

            !Number.isFinite(trialDays) ||

            trialDays < 0 ||

            trialDays > 365

        ) {

            throw new Error(
                "Subscription plan snapshot trial days are invalid."
            );

        }


        this.planSnapshot.trialDays =
            trialDays;


        // =================================================
        // START DATE
        // =================================================

        if (

            !this.startDate ||

            Number.isNaN(
                this.startDate.getTime()
            )

        ) {

            throw new Error(
                "Subscription start date is required."
            );

        }


        // =================================================
        // LIFETIME SUBSCRIPTION
        // =================================================

        if (

            this.planSnapshot.billingCycle ===
            BILLING_CYCLES.LIFETIME

        ) {

            this.endDate = null;

            this.trialStartDate = null;

            this.trialEndDate = null;

        }


        // =================================================
        // NON-LIFETIME SUBSCRIPTION
        // =================================================

        if (

            this.status !==
                SUBSCRIPTION_STATUS.TRIALING &&

            this.planSnapshot.billingCycle !==
                BILLING_CYCLES.LIFETIME &&

            !this.endDate

        ) {

            throw new Error(
                "End date is required for non-lifetime subscriptions."
            );

        }


        // =================================================
        // END DATE VALIDATION
        // =================================================

        if (this.endDate) {

            if (

                Number.isNaN(
                    this.endDate.getTime()
                )

            ) {

                throw new Error(
                    "Subscription end date is invalid."
                );

            }


            if (

                this.endDate <=
                this.startDate

            ) {

                throw new Error(
                    "Subscription end date must be after start date."
                );

            }

        }


        // =================================================
        // TRIALING SUBSCRIPTION
        // =================================================

        if (

            this.status ===
            SUBSCRIPTION_STATUS.TRIALING

        ) {

            // ---------------------------------------------
            // Trial cannot be lifetime
            // ---------------------------------------------

            if (

                this.planSnapshot.billingCycle ===
                BILLING_CYCLES.LIFETIME

            ) {

                throw new Error(
                    "Lifetime subscriptions cannot be trialing."
                );

            }


            // ---------------------------------------------
            // Trial start
            // ---------------------------------------------

            if (

                !this.trialStartDate ||

                Number.isNaN(
                    this.trialStartDate.getTime()
                )

            ) {

                throw new Error(
                    "Trial start date is required."
                );

            }


            // ---------------------------------------------
            // Trial end
            // ---------------------------------------------

            if (

                !this.trialEndDate ||

                Number.isNaN(
                    this.trialEndDate.getTime()
                )

            ) {

                throw new Error(
                    "Trial end date is required."
                );

            }


            // ---------------------------------------------
            // Trial period
            // ---------------------------------------------

            if (

                this.trialEndDate <=
                this.trialStartDate

            ) {

                throw new Error(
                    "Trial end date must be after trial start date."
                );

            }


            // ---------------------------------------------
            // Trial cancellation state
            // ---------------------------------------------

            this.cancelAtPeriodEnd =
                false;

            this.cancelledAt =
                null;

            this.cancellationReason =
                "";

            this.autoRenew =
                false;

        }


        // =================================================
        // ACTIVE SUBSCRIPTION
        // =================================================

        if (

            this.status ===
            SUBSCRIPTION_STATUS.ACTIVE

        ) {

            this.cancelAtPeriodEnd =
                false;

            this.cancelledAt =
                null;

            this.cancellationReason =
                "";

        }


        // =================================================
        // CANCELLED SUBSCRIPTION
        // =================================================

        if (

            this.status ===
            SUBSCRIPTION_STATUS.CANCELLED

        ) {

            if (!this.cancelledAt) {

                this.cancelledAt =
                    new Date();

            }

            this.cancelAtPeriodEnd =
                false;

        }


        // =================================================
        // EXPIRED SUBSCRIPTION
        // =================================================

        if (

            this.status ===
            SUBSCRIPTION_STATUS.EXPIRED

        ) {

            this.cancelAtPeriodEnd =
                false;

        }

    }

);


// =====================================================
// MODEL
// =====================================================

module.exports =
    mongoose.models.Subscription ||
    mongoose.model(
        "Subscription",
        subscriptionSchema
    );