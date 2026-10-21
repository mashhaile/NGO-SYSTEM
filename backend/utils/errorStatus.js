// =====================================================
// ERROR -> HTTP STATUS
// =====================================================
//
// Services mostly throw `new Error("...")` for business
// rules ("Program not found", "... already exists",
// "... must be ..."). Those are the client's problem, not
// a server failure, so they must not come back as 500.
//
// Order:
//   1. explicit statusCode / status (ApiError, http-errors)
//   2. known library errors (Mongoose, JSON body, Multer)
//   3. plain Error thrown by our code -> by wording, else 400
//   4. anything else (TypeError, ReferenceError ...) -> 500
//
// =====================================================

const INTERNAL_MESSAGES = [
    /model is not registered/i,
    /is not implemented/i
];


const statusFromMessage = (message = "") => {

    if (INTERNAL_MESSAGES.some(re => re.test(message))) {
        return 500;
    }

    if (/no authenticated user|not authenticated|token/i.test(message)) {
        return 401;
    }

    if (/not found|does not exist|no .* found/i.test(message)) {
        return 404;
    }

    if (/already|duplicate|exists/i.test(message)) {
        return 409;
    }

    if (/permission|not allowed|forbidden|unauthori[sz]ed|access denied|no active subscription/i.test(message)) {
        return 403;
    }

    return 400;

};


const getErrorStatus = (err) => {

    if (!err) {
        return 500;
    }

    const explicit =
        Number(err.statusCode || err.status);

    if (explicit >= 400 && explicit < 600) {
        return explicit;
    }

    // Invalid ObjectId or a value of the wrong type

    if (err.name === "CastError") {
        return 400;
    }

    if (err.name === "ValidationError") {
        return 400;
    }

    // Unique index

    if (err.code === 11000) {
        return 409;
    }

    // Malformed JSON body

    if (err.type === "entity.parse.failed") {
        return 400;
    }

    if (err.name === "MulterError") {
        return 400;
    }

    // Plain `new Error(...)` thrown by our own code

    if (err.constructor === Error) {
        return statusFromMessage(err.message);
    }

    return 500;

};


// Message safe to show the client.

const getErrorMessage = (err) => {

    const status =
        getErrorStatus(err);

    if (err?.name === "CastError") {
        return err.path === "_id" || !err.path
            ? "Invalid ID."
            : `Invalid ${err.path}.`;
    }

    if (err?.name === "ValidationError" && err.errors) {
        return Object.values(err.errors)
            .map(item => item.message)
            .join(" ");
    }

    if (err?.code === 11000) {
        const field =
            Object.keys(err.keyValue || err.keyPattern || {})[0];
        return field
            ? `A record with this ${field} already exists.`
            : "This record already exists.";
    }

    if (err?.type === "entity.parse.failed") {
        return "The request body is not valid JSON.";
    }

    // Do not leak internals of real server failures in
    // production; they are logged instead.

    if (status >= 500 && process.env.NODE_ENV === "production") {
        return "Something went wrong. Please try again.";
    }

    return err?.message || "Internal Server Error";

};


module.exports = {
    getErrorStatus,
    getErrorMessage
};
