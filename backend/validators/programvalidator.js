const { WORK_STATUS_INPUT } = require("../constants/workStatus");
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
        .valid(...WORK_STATUS_INPUT)
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

    targetBeneficiaries: Joi.number()
        .integer()
        .min(0),

    startDate: Joi.date(),

    endDate: Joi.date()
        .allow(null),

    status: Joi.string()
        .valid(...WORK_STATUS_INPUT)

}).min(1);


module.exports = {
    createProgramSchema,
    updateProgramSchema
};