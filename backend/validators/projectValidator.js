const { WORK_STATUS_INPUT } = require("../constants/workStatus");
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
    // a phase of this main project
    parentProject:
        Joi.string()
            .allow(null, ""),
    startDate:
        Joi.date()
            .required(),

    endDate:
        Joi.date()
            .required(),

    status:
        Joi.string()
            .valid(...WORK_STATUS_INPUT)
            .default("Planned")

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
    parentProject:
        Joi.string()
            .allow(null, ""),
    startDate:
        Joi.date(),

    endDate:
        Joi.date(),

    status:
        Joi.string()
            .valid(...WORK_STATUS_INPUT)

});