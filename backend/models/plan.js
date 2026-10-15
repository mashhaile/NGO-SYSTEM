const mongoose =
    require("mongoose");

const {
    BILLING_CYCLES
} =
    require("../config/constants");


// =====================================================
// PLAN SCHEMA
// =====================================================

const planSchema = new mongoose.Schema(

    {

        // =================================================
        // BASIC PLAN INFORMATION
        // =================================================

        name: {

            type: String,

            required: true,

            unique: true,

            trim: true,

            maxlength: 100

        },


        code: {

            type: String,

            required: true,

            unique: true,

            uppercase: true,

            trim: true,

            maxlength: 50,

            immutable: true

        },


        description: {

            type: String,

            default: "",

            trim: true,

            maxlength: 500

        },


        // =================================================
        // PRICING
        // =================================================

        price: {

            type: Number,

            required: true,

            default: 0,

            min: 0

        },


        currency: {

            type: String,

            required: true,

            default: "USD",

            uppercase: true,

            trim: true,

            minlength: 3,

            maxlength: 3,

            match: /^[A-Z]{3}$/

        },


        billingCycle: {

            type: String,

            enum: Object.values(
                BILLING_CYCLES
            ),

            required: true,

            default:
                BILLING_CYCLES.MONTHLY

        },


        // =================================================
        // RESOURCE LIMITS
        //
        // -1 = unlimited
        //  0 = none
        // >0 = maximum allowed
        //
        // Limits control quantities.
        // They do NOT control module access.
        // =================================================

        limits: {

            users: {

                type: Number,

                default: 5,

                min: -1

            },


            beneficiaries: {

                type: Number,

                default: 100,

                min: -1

            },


            enterprises: {

                type: Number,

                default: 50,

                min: -1

            },


            donors: {

                type: Number,

                default: 100,

                min: -1

            },


            donations: {

                type: Number,

                default: 100,

                min: -1

            },


            programs: {

                type: Number,

                default: 10,

                min: -1

            },


            projects: {

                type: Number,

                default: 20,

                min: -1

            },


            activities: {

                type: Number,

                default: 100,

                min: -1

            },


            activityRuns: {

                type: Number,

                default: 500,

                min: -1

            },


            enrollments: {

                type: Number,

                default: 500,

                min: -1

            },


            serviceDeliveries: {

                type: Number,

                default: 500,

                min: -1

            },


            attendanceRecords: {

                type: Number,

                default: 1000,

                min: -1

            },


            customFields: {

                type: Number,

                default: 50,

                min: -1

            },


            storageMB: {

                type: Number,

                default: 500,

                min: -1

            }

        },


        // =================================================
        // FEATURES
        //
        // Features are commercial capabilities.
        // =================================================

        features: {

            dashboard: {

                type: Boolean,

                default: true

            },


            reports: {

                type: Boolean,

                default: true

            },


            exports: {

                json: {

                    type: Boolean,

                    default: true

                },


                excel: {

                    type: Boolean,

                    default: false

                },


                csv: {

                    type: Boolean,

                    default: false

                },


                pdf: {

                    type: Boolean,

                    default: false

                }

            },


            apiAccess: {

                type: Boolean,

                default: false

            },


            customFields: {

                type: Boolean,

                default: false

            },


            notifications: {

                type: Boolean,

                default: true

            },


            aiReports: {

                type: Boolean,

                default: false

            },


            scheduledReports: {

                type: Boolean,

                default: false

            },


            automation: {

                type: Boolean,

                default: false

            }

        },


        // =================================================
        // TRIAL
        // =================================================

        trialDays: {

            type: Number,

            default: 0,

            min: 0,

            max: 365

        },


        // =================================================
        // PLAN LIFECYCLE
        // =================================================

        isActive: {

            type: Boolean,

            default: true,

            index: true

        },


        // =================================================
        // PUBLIC / COMMERCIAL VISIBILITY
        // =================================================

        isPublic: {

            type: Boolean,

            default: true,

            index: true

        },


        // =================================================
        // DISPLAY ORDER
        // =================================================

        sortOrder: {

            type: Number,

            default: 0,

            min: 0

        }

    },

    {

        timestamps: true

    }

);


// =====================================================
// NORMALIZE PLAN CODE / CURRENCY
// =====================================================

planSchema.pre(

    "save",

    function(next) {

        if (this.code) {

            this.code =
                this.code
                    .trim()
                    .toUpperCase();

        }


        if (this.currency) {

            this.currency =
                this.currency
                    .trim()
                    .toUpperCase();

        }


        next();

    }

);


// =====================================================
// INDEXES
// =====================================================

planSchema.index({

    isActive: 1,

    isPublic: 1,

    sortOrder: 1

});


// =====================================================
// MODEL
// =====================================================

module.exports =
    mongoose.models.Plan ||
    mongoose.model(
        "Plan",
        planSchema
    );