const Joi = require("joi");

// ==========================================
// CREATE PROGRAM VALIDATION
// ==========================================

const createProgramSchema = Joi.object({

    name: Joi.string()
        .trim()
        .min(3)
        .max(100)
        .required(),

    description: Joi.string()
        .allow("")
        .optional(),

    category: Joi.string()
        .allow("")
        .optional(),

    budget: Joi.number()
        .min(0)
        .default(0),

    targetBeneficiaries: Joi.number()
        .integer()
        .min(0)
        .default(0),

    startDate: Joi.date()
        .required(),

    endDate: Joi.date()
        .greater(Joi.ref("startDate"))
        .allow(null)
        .optional(),

    status: Joi.string()
        .valid(
            "Planned",
            "Active",
            "Completed",
            "Suspended",
            "Cancelled"
        )
        .default("Planned")

});


// ==========================================
// UPDATE PROGRAM VALIDATION
// ==========================================

const updateProgramSchema = Joi.object({

    name: Joi.string()
        .trim()
        .min(3)
        .max(100),

    description: Joi.string()
        .allow(null, ""),

    category: Joi.string()
        .allow(null, ""),

    budget: Joi.number()
        .min(0),

    targetBeneficiaries: Joi.number()
        .integer()
        .min(0),

    startDate: Joi.date(),

    endDate: Joi.date()
        .allow(null),

    status: Joi.string()
        .valid(
            "Planned",
            "Active",
            "Completed",
            "Suspended",
            "Cancelled"
        )

}).min(1);


module.exports = {
    createProgramSchema,
    updateProgramSchema
};