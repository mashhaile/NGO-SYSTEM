const Joi = require("joi");


// ======================================================
// CREATE PROJECT
// ======================================================

exports.createProjectSchema = Joi.object({

    program:
        Joi.string()
            .required(),

    name:
        Joi.string()
            .trim()
            .min(3)
            .required(),

    description:
        Joi.string()
            .allow("")
            .allow(null),

    donor:
        Joi.string()
            .allow(null),

    projectManager:
        Joi.string()
            .allow(null),

    approvedBudget:
        Joi.number()
            .min(0)
            .default(0),

    startDate:
        Joi.date()
            .required(),

    endDate:
        Joi.date()
            .required(),

    status:
        Joi.string()
            .valid(
                "Draft",
                "Active",
                "Completed",
                "Cancelled"
            )
            .default("Draft")

});


// ======================================================
// UPDATE PROJECT
// ======================================================

exports.updateProjectSchema = Joi.object({

    program:
        Joi.string(),

    name:
        Joi.string()
            .trim()
            .min(3),

    description:
        Joi.string()
            .allow("")
            .allow(null),

    donor:
        Joi.string()
            .allow(null),

    projectManager:
        Joi.string()
            .allow(null),

    approvedBudget:
        Joi.number()
            .min(0),

    startDate:
        Joi.date(),

    endDate:
        Joi.date(),

    status:
        Joi.string()
            .valid(
                "Draft",
                "Active",
                "Completed",
                "Cancelled"
            )

});