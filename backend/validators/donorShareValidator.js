const Joi = require("joi");


const objectId =
    Joi.string()
        .pattern(/^[0-9a-fA-F]{24}$/)
        .messages({
            "string.pattern.base":
                "{{#label}} must be a valid id."
        });


// Share link for one donor; donation empty = all of
// the donor's donations.

const createShareLinkSchema =
    Joi.object({

        donor:
            objectId.required(),

        donation:
            objectId.allow("", null),

        expiresInDays:
            Joi.number()
                .valid(30, 90, 180, 365)
                .default(90),

        label:
            Joi.string()
                .trim()
                .max(120)
                .allow("", null)

    });


module.exports = {
    createShareLinkSchema
};
