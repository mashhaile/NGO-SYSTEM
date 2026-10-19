const Joi = require("joi");


// ==========================================
// CREATE DONOR VALIDATION
// ==========================================

const createDonorSchema = Joi.object({

    name:
        Joi.string()
            .trim()
            .min(2)
            .max(150)
            .required(),

    donorType:
        Joi.string()
            .valid(
                "Individual",
                "Organization",
                "Government",
                "NGO",
                "Corporate",
                "Foundation"
            )
            .default("Organization"),

    email:
        Joi.string()
            .trim()
            .email()
            .allow("", null),

    phone:
        Joi.string()
            .trim()
            .allow("", null),

    address:
        Joi.string()
            .trim()
            .allow("", null),

    country:
        Joi.string()
            .trim()
            .allow("", null),

    website:
        Joi.string()
            .trim()
            .allow("", null),

    registrationNumber:
        Joi.string()
            .trim()
            .allow("", null),

    donorSince:
        Joi.date()
            .allow("", null),

    lastContactDate:
        Joi.date()
            .allow("", null),

    nextFollowUpDate:
        Joi.date()
            .allow("", null),

    contactPerson:
        Joi.string()
            .trim()
            .allow("", null),

    status:
        Joi.string()
            .valid(
                "Active",
                "Inactive"
            )
            .default("Active"),

    notes:
        Joi.string()
            .allow("", null),

    shareBeneficiaryNames:
        Joi.boolean()
            .default(false)

});


// ==========================================
// UPDATE DONOR VALIDATION
// ==========================================

const updateDonorSchema = Joi.object({

    name:
        Joi.string()
            .trim()
            .min(2)
            .max(150),

    donorType:
        Joi.string()
            .valid(
                "Individual",
                "Organization",
                "Government",
                "NGO",
                "Corporate",
                "Foundation"
            ),

    email:
        Joi.string()
            .trim()
            .email()
            .allow("", null),

    phone:
        Joi.string()
            .trim()
            .allow("", null),

    address:
        Joi.string()
            .trim()
            .allow("", null),

    country:
        Joi.string()
            .trim()
            .allow("", null),

    website:
        Joi.string()
            .trim()
            .allow("", null),

    registrationNumber:
        Joi.string()
            .trim()
            .allow("", null),

    donorSince:
        Joi.date()
            .allow("", null),

    lastContactDate:
        Joi.date()
            .allow("", null),

    nextFollowUpDate:
        Joi.date()
            .allow("", null),

    contactPerson:
        Joi.string()
            .trim()
            .allow("", null),

    status:
        Joi.string()
            .valid(
                "Active",
                "Inactive"
            ),

    notes:
        Joi.string()
            .allow("", null),

    shareBeneficiaryNames:
        Joi.boolean()

})
.min(1);


module.exports = {

    createDonorSchema,

    updateDonorSchema

};
