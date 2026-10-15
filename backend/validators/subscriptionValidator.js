const Joi =
    require("joi");


// =====================================================
// COMMON OBJECT ID
// =====================================================

const objectId =
    Joi.string()
        .trim()
        .pattern(
            /^[0-9a-fA-F]{24}$/
        )
        .messages({

            "string.empty":
                "Value cannot be empty.",

            "string.pattern.base":
                "Must be a valid MongoDB ObjectId.",

            "any.required":
                "Value is required."

        });


// =====================================================
// CREATE / ASSIGN SUBSCRIPTION
// =====================================================
//
// trialDays is intentionally NOT accepted here.
//
// The trial period comes from the selected Plan.
// The backend calculates:
// - trialStartDate
// - trialEndDate
// - subscription status
// - paid subscription endDate
//
// =====================================================

const createSubscriptionSchema =
    Joi.object({

        organizationId:

            objectId
                .required()
                .messages({

                    "any.required":
                        "Organization ID is required."

                }),


        planId:

            objectId
                .required()
                .messages({

                    "any.required":
                        "Plan ID is required."

                }),


        startDate:

            Joi.date()
                .iso()
                .optional()
                .messages({

                    "date.base":
                        "Start date must be a valid date.",

                    "date.format":
                        "Start date must be a valid ISO date."

                })

    })
        .unknown(false);


// =====================================================
// CHANGE PLAN
// =====================================================
//
// Changing a plan is controlled by Super Admin.
// The backend determines the new subscription period.
//
// =====================================================

const changePlanSchema =
    Joi.object({

        planId:

            objectId
                .required()
                .messages({

                    "any.required":
                        "Plan ID is required."

                })

    })
        .unknown(false);


// =====================================================
// RENEW SUBSCRIPTION
// =====================================================
//
// No request body is required.
//
// organizationId comes from the URL parameter.
//
// The backend determines:
// - current subscription
// - billing cycle
// - renewal start date
// - renewal end date
//
// =====================================================

const renewSubscriptionSchema =
    Joi.object({})
        .unknown(false);


// =====================================================
// CANCEL SUBSCRIPTION
// =====================================================

const cancelSubscriptionSchema =
    Joi.object({

        reason:

            Joi.string()
                .trim()
                .max(500)
                .allow("")
                .optional()
                .messages({

                    "string.max":
                        "Cancellation reason cannot exceed 500 characters."

                })

    })
        .unknown(false);


// =====================================================
// EXPORTS
// =====================================================

module.exports = {

    createSubscriptionSchema,

    changePlanSchema,

    renewSubscriptionSchema,

    cancelSubscriptionSchema

};