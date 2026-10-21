const ApiResponse =
    require("../utils/apiresponse");

const {
    getErrorStatus,
    getErrorMessage
} = require("../utils/errorStatus");


const errorHandler = (
    err,
    req,
    res,
    next
) => {

    const statusCode =
        getErrorStatus(err);

    // Full details only for real server failures;
    // client errors are expected and logged briefly.

    if (statusCode >= 500) {
        console.error(err);
    }
    else {
        console.warn(
            `${statusCode} ${req.method} ${req.originalUrl}: ${err.message}`
        );
    }

    if (res.headersSent) {
        return next(err);
    }

    return ApiResponse.error(

        res,

        statusCode,

        getErrorMessage(err),

        err.errors && Array.isArray(err.errors)
            ? err.errors
            : []

    );

};


module.exports =
    errorHandler;
