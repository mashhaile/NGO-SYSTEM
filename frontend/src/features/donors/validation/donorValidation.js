import Joi from "joi";


// ==========================================
// CREATE DONOR VALIDATION
// ==========================================

export const donorSchema = Joi.object({

    name:
        Joi.string()
        .required()
        .messages({

            "string.empty":
            "Donor name is required"

        }),


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
        .required(),


    email:
        Joi.string()
        .email()
        .allow("")
        .allow(null),


    phone:
        Joi.string()
        .allow("")
        .allow(null),


    address:
        Joi.string()
        .allow("")
        .allow(null),


    contactPerson:
        Joi.string()
        .allow("")
        .allow(null),


    status:
        Joi.string()
        .valid(
            "Active",
            "Inactive"
        )
        .default("Active"),


    notes:
        Joi.string()
        .allow("")
        .allow(null)

});