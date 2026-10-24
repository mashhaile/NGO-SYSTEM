const Joi = require("joi");

const { CURRENCY_CODES } = require("../config/currencies");

// ETB, USD, EUR, GBP, CHF (config/currencies.js)
const currencyCode =
    Joi.string()
        .trim()
        .uppercase()
        .valid(...CURRENCY_CODES)
        .messages({ "any.only": `Currency must be one of ${CURRENCY_CODES.join(", ")}.` });


// =====================================================
// TOR VALIDATORS
// =====================================================
//
// Status is never accepted here: it only changes
// through submit / approve / return.
//
// =====================================================

const objectId =
    Joi.string()
        .pattern(/^[0-9a-fA-F]{24}$/)
        .messages({
            "string.pattern.base":
                "{{#label}} must be a valid id."
        });


const text =
    Joi.string()
        .trim()
        .allow("", null);


const budgetLine =
    Joi.object({

        _id:
            objectId.optional(),

        description:
            Joi.string()
                .trim()
                .required()
                .messages({
                    "any.required":
                        "Each budget line needs a description.",
                    "string.empty":
                        "Each budget line needs a description."
                }),

        unit:
            text,

        quantity:
            Joi.number()
                .min(0)
                .default(1),

        unitCost:
            Joi.number()
                .min(0)
                .default(0)

    });


const ACTIVITY_TYPES = [
    "Training",
    "Workshop",
    "Seminar",
    "Meeting",
    "Conference",
    "Awareness Campaign",
    "Field Visit",
    "Monitoring Visit",
    "Assessment",
    "Distribution",
    "Community Dialogue",
    "Other"
];


const torFields = {

    // Optional: usually linked after approval.

    activity:
        objectId.allow("", null),

    activityRun:
        objectId.allow("", null),

    activityType:
        Joi.string()
            .valid(...ACTIVITY_TYPES)
            .allow("", null),

    background: text,

    objectives: text,

    expectedOutputs: text,

    methodology: text,

    participants: text,

    expectedParticipants:
        Joi.number()
            .integer()
            .min(0)
            .allow(null),

    facilitators: text,

    logistics: text,

    reportingRequirements: text,

    startDate:
        Joi.date()
            .allow("", null),

    endDate:
        Joi.date()
            .allow("", null),

    region: text,
    regionCode: text,
    zone: text,
    zoneCode: text,
    woreda: text,
    woredaCode: text,

    venue: text,

    // 3-letter code (ETB, USD, ...): free text let amounts
    // be typed into it ("ETB5000000")
    currency:
        currencyCode
            .allow("", null),

    budgetLines:
        Joi.array()
            .items(budgetLine)

};


const createTorSchema =
    Joi.object({

        title:
            Joi.string()
                .trim()
                .required(),

        project:
            objectId.required(),

        ...torFields

    });


const updateTorSchema =
    Joi.object({

        title:
            Joi.string()
                .trim(),

        project:
            objectId,

        ...torFields

    })
        .min(1);


const returnTorSchema =
    Joi.object({

        comment:
            Joi.string()
                .trim()
                .min(3)
                .required()
                .messages({
                    "any.required":
                        "A comment is required when returning a TOR.",
                    "string.empty":
                        "A comment is required when returning a TOR."
                })

    });


const approveTorSchema =
    Joi.object({

        comment: text

    });


// Name / type of the activity linked to the TOR.

const updateLinkedActivitySchema =
    Joi.object({

        name:
            Joi.string()
                .trim()
                .min(3)
                .messages({
                    "string.min":
                        "Activity name must be at least 3 characters."
                }),

        activityType:
            Joi.string()
                .valid(...ACTIVITY_TYPES)

    })
        .min(1);


const linkActivitySchema =
    Joi.object({

        activity:
            objectId.required()

    });


module.exports = {
    updateLinkedActivitySchema,
    linkActivitySchema,
    createTorSchema,
    updateTorSchema,
    returnTorSchema,
    approveTorSchema
};
