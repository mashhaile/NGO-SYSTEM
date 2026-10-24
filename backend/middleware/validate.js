const ApiError =
    require("../utils/apiError");


// "\"startDate\" must be a valid date" -> "Start date must be a valid date."
const humanize = (message = "") => {

    const text =
        String(message)
            .replace(/"([^"]+)"/g, (match, field) =>
                field.split(".").pop().replace(/([a-z])([A-Z])/g, "$1 $2").toLowerCase()
            )
            .trim();

    const sentence = text.charAt(0).toUpperCase() + text.slice(1);

    return /[.!?]$/.test(sentence) ? sentence : `${sentence}.`;

};


const validate = (
    schema
) => {

    return (
        req,
        res,
        next
    ) => {

        // ==================================================
        // VALIDATE SCHEMA
        // ==================================================

        if (
            !schema ||
            typeof schema.validate !== "function"
        ) {

            return next(

                new ApiError(

                    "Validation schema is required.",

                    500

                )

            );

        }


        // ==================================================
        // VALIDATE REQUEST BODY
        // ==================================================

        const {
            error,
            value
        } =
            schema.validate(

                req.body,

                {

                    abortEarly:
                        false,

                    stripUnknown:
                        true

                }

            );


        // ==================================================
        // VALIDATION FAILED
        // ==================================================

        if (error) {

            const errors =
                error.details.map(

                    detail => ({

                        field:
                            detail.path.join("."),

                        message:
                            detail.message

                    })

                );


            // Say which field is wrong ("Start date must be a
            // valid date."), not only "Validation failed."
            const readable =
                [...new Set(errors.map(item => humanize(item.message)))].join(" ");

            return next(

                new ApiError(

                    readable ? `Please check: ${readable}` : "Validation failed.",

                    400,

                    errors

                )

            );

        }


        // ==================================================
        // USE CLEANED/Joi-VALIDATED DATA
        // ==================================================

        req.body =
            value;


        return next();

    };

};


module.exports =
    validate;