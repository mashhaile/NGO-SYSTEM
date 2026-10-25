const { WORK_STATUS_INPUT } = require("../constants/workStatus");
const Joi = require("joi");


// ======================================================
// CREATE ACTIVITY RUN
// ======================================================

const createActivityRunSchema = Joi.object({

    // --------------------------------------------------
    // Parent Activity
    // --------------------------------------------------

    activity:
        Joi.string()
            .required(),


    // --------------------------------------------------
    // Run Information
    // --------------------------------------------------

    name:
        Joi.string()
            .trim()
            .min(3)
            .required(),


    startDate:
        Joi.date()
            .required(),


    endDate:
        Joi.date()
            .allow(null)
            .default(null)
            .min(Joi.ref("startDate")),


    region:
        Joi.string()
            .trim()
            .allow("", null)
            .default(null),

    regionCode:
        Joi.string()
            .trim()
            .allow("", null)
            .default(null),

    zone:
        Joi.string()
            .trim()
            .allow("", null)
            .default(null),

    zoneCode:
        Joi.string()
            .trim()
            .allow("", null)
            .default(null),

    woreda:
        Joi.string()
            .trim()
            .allow("", null)
            .default(null),

    woredaCode:
        Joi.string()
            .trim()
            .allow("", null)
            .default(null),

    location:
        Joi.string()
            .trim()
            .allow("", null)
            .default(null),


    // --------------------------------------------------
    // Trainer
    // User ID
    // --------------------------------------------------

    trainer:
        Joi.string()
            .allow(null)
            .default(null),


    // --------------------------------------------------
    // Target Group
    // --------------------------------------------------

    targetGroup:
        Joi.string()
            .trim()
            .allow("", null)
            .default(null),


    // --------------------------------------------------
    // Status
    // --------------------------------------------------

    status:
        Joi.string()
            .valid(...WORK_STATUS_INPUT)
            .default("Planned"),


    // --------------------------------------------------
    // Notes
    // --------------------------------------------------

    notes:
        Joi.string()
            .trim()
            .allow("", null)
            .default(null)

});



// ======================================================
// UPDATE ACTIVITY RUN
// ======================================================
//
// IMPORTANT:
//
// activity      ❌ cannot change
// project       ❌ cannot change
// program       ❌ cannot change
// runCode       ❌ cannot change
//
// Only operational information can be updated.
// ======================================================

const updateActivityRunSchema = Joi.object({

    name:
        Joi.string()
            .trim()
            .min(3),


    startDate:
        Joi.date(),


    endDate:
        Joi.date()
            .allow(null),


    region:
        Joi.string()
            .trim()
            .allow("", null),

    regionCode:
        Joi.string()
            .trim()
            .allow("", null),

    zone:
        Joi.string()
            .trim()
            .allow("", null),

    zoneCode:
        Joi.string()
            .trim()
            .allow("", null),

    woreda:
        Joi.string()
            .trim()
            .allow("", null),

    woredaCode:
        Joi.string()
            .trim()
            .allow("", null),

    location:
        Joi.string()
            .trim()
            .allow("", null),


    trainer:
        Joi.string()
            .allow(null),


    targetGroup:
        Joi.string()
            .trim()
            .allow("", null),


    status:
        Joi.string()
            .valid(...WORK_STATUS_INPUT),


    notes:
        Joi.string()
            .trim()
            .allow("", null)

})
    .min(1);



// ======================================================
// EXPORTS
// ======================================================

module.exports = {

    createActivityRunSchema,

    updateActivityRunSchema

};