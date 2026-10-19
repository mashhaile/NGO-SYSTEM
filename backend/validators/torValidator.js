const Joi = require("joi");


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


const torFields = {

    activityRun:
        objectId.allow("", null),

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

    currency:
        Joi.string()
            .trim()
            .max(10)
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

        activity:
            objectId.required(),

        ...torFields

    });


const updateTorSchema =
    Joi.object({

        title:
            Joi.string()
                .trim(),

        activity:
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


module.exports = {
    createTorSchema,
    updateTorSchema,
    returnTorSchema,
    approveTorSchema
};
