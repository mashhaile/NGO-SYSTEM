const Joi = require("joi");

const {
    isReservedCustomFieldKey
} = require("../utils/customFieldReservedKeys");


// ==========================================================
// CREATE CUSTOM FIELD
// ==========================================================

const createCustomFieldSchema = Joi.object({

    module: Joi.string()
    .valid(
        "Beneficiary",
        "Donor",
        "Program",
        "ServiceDelivery",
        "User",
        "Enterprise",
        "EnterpriseMember"
    )
    .required(),


    label: Joi.string()
        .trim()
        .required(),


    key: Joi.string()
        .trim()
        .required(),


    type: Joi.string()
        .valid(
            "text",
            "number",
            "date",
            "select",
            "checkbox",
            "textarea"
        )
        .required(),


    // ======================================================
    // SELECT OPTIONS
    // ======================================================

    options: Joi.array()
        .items(
            Joi.object({

                label: Joi.string()
                    .trim()
                    .required(),

                value: Joi.string()
                    .trim()
                    .required()

            })
        )
        .optional(),


    required: Joi.boolean()
        .optional()

})

.custom((value, helpers) => {

    if (
        isReservedCustomFieldKey(
            value.module,
            value.key
        )
    ) {

        return helpers.error(
            "any.reservedCustomFieldKey",
            {
                key:
                    String(value.key)
                        .trim()
                        .toLowerCase(),

                module:
                    value.module
            }
        );

    }


    return value;

})

.messages({

    "any.reservedCustomFieldKey":
        "Custom field key \"{{#key}}\" is reserved for the {{#module}} module."

});


// ==========================================================
// UPDATE CUSTOM FIELD
// ==========================================================

const updateCustomFieldSchema = Joi.object({

    module: Joi.any()
        .forbidden(),

    key: Joi.any()
        .forbidden(),

    label: Joi.string()
        .trim()
        .optional(),


    type: Joi.string()
        .valid(
            "text",
            "number",
            "date",
            "select",
            "checkbox",
            "textarea"
        )
        .optional(),


    options: Joi.array()
        .items(
            Joi.object({

                label: Joi.string()
                    .trim()
                    .required(),

                value: Joi.string()
                    .trim()
                    .required()

            })
        )
        .optional(),


    required: Joi.boolean()
        .optional(),


    active: Joi.boolean()
        .optional()

});


// ==========================================================
// EXPORT
// ==========================================================

module.exports = {

    createCustomFieldSchema,

    updateCustomFieldSchema

};

