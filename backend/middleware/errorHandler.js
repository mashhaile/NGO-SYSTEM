const ApiResponse =
    require("../utils/ApiResponse");


const errorHandler = (
    err,
    req,
    res,
    next
) => {

    console.error(
        err
    );


    const statusCode =
        err.statusCode || 500;


    const message =
        err.message ||
        "Internal Server Error";


    const errors =
        err.errors || [];


    return ApiResponse.error(

        res,

        statusCode,

        message,

        errors

    );

};


module.exports =
    errorHandler;