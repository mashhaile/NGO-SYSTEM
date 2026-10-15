const ApiError =
    require("../utils/ApiError");


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


            return next(

                new ApiError(

                    "Validation failed.",

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