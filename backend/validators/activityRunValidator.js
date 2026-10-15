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
            .valid(

                "Planned",

                "Active",

                "Completed",

                "Cancelled"

            )
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
            .valid(

                "Planned",

                "Active",

                "Completed",

                "Cancelled"

            ),


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