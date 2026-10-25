const Joi = require("joi");



// ==========================================
// CREATE
// ==========================================

const createEnrollmentSchema = Joi.object({

    program:

        Joi.string()

        .required(),


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


});





// ==========================================
// UPDATE
// ==========================================

const updateEnrollmentSchema = Joi.object({

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