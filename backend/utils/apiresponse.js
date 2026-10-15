class ApiResponse {

    // ==========================================
    // SUCCESS RESPONSE
    // ==========================================

    static success(
        res,
        statusCode = 200,
        message = "Success",
        data = null
    ) {

        return res
            .status(statusCode)
            .json({

                success: true,

                message,

                data

            });

    }


    // ==========================================
    // ERROR RESPONSE
    // ==========================================

    static error(
        res,
        statusCode = 500,
        message = "Something went wrong",
        errors = []
    ) {

        return res
            .status(statusCode)
            .json({

                success: false,

                message,

                errors

            });

    }

}


module.exports = ApiResponse;