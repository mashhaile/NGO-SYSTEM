const Joi = require("joi");



const organizationValidator = Joi.object({


    name:Joi.string()
    .min(3)
    .required(),


    email:Joi.string()
    .email()
    .required(),


    phone:Joi.string()
    .required(),


    country:Joi.string()
    .required(),


    address:Joi.string()
    .allow(""),


    website:Joi.string()
    .allow(""),



    admin:Joi.object({


        name:Joi.string()
        .required(),


        email:Joi.string()
        .email()
        .required(),


        password:Joi.string()
        .min(6)
        .required()


    })

    .required()


});



module.exports =
organizationValidator;