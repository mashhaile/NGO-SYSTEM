const Joi = require("joi");



// ==========================================
// CREATE
// ==========================================

// project (or a phase): the program comes from it. Older
// clients may still send only the program.
const createEnrollmentSchema = Joi.object({

    program:

        Joi.string()

        .allow("", null),


    project:

        Joi.string()

        .allow("", null),


    beneficiary:

        Joi.string()

        .required(),


    enrollmentDate:

        Joi.date()

        .optional(),


    status:

        Joi.string()

        .valid(
"Pending",
            "Active",

            "Completed",

            "Dropped",

        "Suspended"

        )

        .default("Active"),


    remarks:

        Joi.string()

        .allow("", null)

        .optional()


}).or("program", "project");





// ==========================================
// UPDATE
// ==========================================

const updateEnrollmentSchema = Joi.object({

    // an older enrollment (without a project) can be given its project
    project:

        Joi.string(),


    status:

        Joi.string()

        .valid(
"Pending",
            "Active",

            "Completed",

            "Dropped",

        "Suspended"

        ),


    enrollmentDate:

        Joi.date(),


    remarks:

        Joi.string()

        .allow("", null)


}).min(1);





module.exports = {

    createEnrollmentSchema,

    updateEnrollmentSchema

};