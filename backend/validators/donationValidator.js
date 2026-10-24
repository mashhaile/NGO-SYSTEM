const Joi = require("joi");


// ==========================================
// OBJECT ID
// ==========================================

const objectId = Joi.string()
    .pattern(/^[0-9a-fA-F]{24}$/)
    .messages({
        "string.pattern.base":
            "Invalid ID format"
    });


// ==========================================
// CREATE DONATION VALIDATOR
// ==========================================

const createDonationSchema = Joi.object({

    donor:
        objectId
            .required()
            .messages({
                "any.required":
                    "Donor is required",

                "string.empty":
                    "Donor is required",

                "string.pattern.base":
                    "Invalid donor ID"
            }),


    program:
        objectId
            .allow(null, "")
            .optional()
            .messages({
                "string.pattern.base":
                    "Invalid program ID"
            }),


    project:
        objectId
            .allow(null, "")
            .optional()
            .messages({
                "string.pattern.base":
                    "Invalid project ID"
            }),


    // ======================================
    // ACTIVITY
    // ======================================

    activity:
        objectId
            .allow(null, "")
            .optional()
            .messages({
                "string.pattern.base":
                    "Invalid activity ID"
            }),


    // ======================================
    // ACTIVITY RUN
    // ======================================

    activityRun:
        objectId
            .allow(null, "")
            .optional()
            .messages({
                "string.pattern.base":
                    "Invalid activity run ID"
            }),


    title:
        Joi.string()
            .trim()
            .required()
            .messages({
                "any.required":
                    "Donation title is required",

                "string.empty":
                    "Donation title is required"
            }),


    amount:
        Joi.number()
            .min(0)
            .required()
            .messages({
                "any.required":
                    "Donation amount is required",

                "number.base":
                    "Donation amount must be a number",

                "number.min":
                    "Donation amount cannot be negative"
            }),


    currency:
        Joi.string()
            .valid(
                "USD",
                "ETB",
                "EUR",
                "GBP"
            )
            .default("USD"),

    // 1 unit of the currency = ? ETB, on the day it was received
    receivedRate:
        Joi.number()
            .greater(0)
            .allow(null, "")
            .messages({
                "number.base": "The exchange rate must be a number.",
                "number.greater": "The exchange rate must be more than 0."
            }),

    receivedRateDate:
        Joi.date()
            .allow(null, ""),


    donationDate:
        Joi.date()
            .required()
            .messages({
                "any.required":
                    "Donation date is required",

                "date.base":
                    "Invalid donation date"
            }),


    financialYear:
        Joi.string()
            .trim()
            .allow(null, "")
            .optional(),


    fundingSource:
        Joi.string()
            .valid(
                "Grant",
                "Donation",
                "Government Funding",
                "Corporate CSR",
                "Internal",
                "Other"
            )
            .default("Donation"),


    fundingRestriction:
        Joi.string()
            .valid(
                "Restricted",
                "Unrestricted"
            )
            .default("Unrestricted"),


    donationType:
        Joi.string()
            .valid(
                "Cash",
                "Bank Transfer",
                "Material",
                "Equipment",
                "Service",
                "Other"
            )
            .default("Cash"),


    status:
        Joi.string()
            .valid(
                "Pledged",
                "Received",
                "Cancelled"
            )
            .default("Received"),


    receiptNumber:
        Joi.string()
            .trim()
            .allow(null, "")
            .optional(),


    referenceNumber:
        Joi.string()
            .trim()
            .allow(null, "")
            .optional(),


    description:
        Joi.string()
            .trim()
            .allow(null, "")
            .optional()

});


// ==========================================
// UPDATE DONATION VALIDATOR
// ==========================================

const updateDonationSchema = Joi.object({

    donor:
        objectId
            .optional()
            .messages({
                "string.pattern.base":
                    "Invalid donor ID"
            }),


    program:
        objectId
            .allow(null, "")
            .optional()
            .messages({
                "string.pattern.base":
                    "Invalid program ID"
            }),


    project:
        objectId
            .allow(null, "")
            .optional()
            .messages({
                "string.pattern.base":
                    "Invalid project ID"
            }),


    // ======================================
    // ACTIVITY
    // ======================================

    activity:
        objectId
            .allow(null, "")
            .optional()
            .messages({
                "string.pattern.base":
                    "Invalid activity ID"
            }),


    // ======================================
    // ACTIVITY RUN
    // ======================================

    activityRun:
        objectId
            .allow(null, "")
            .optional()
            .messages({
                "string.pattern.base":
                    "Invalid activity run ID"
            }),


    title:
        Joi.string()
            .trim()
            .optional(),


    amount:
        Joi.number()
            .min(0)
            .optional(),


    currency:
        Joi.string()
            .valid(
                "USD",
                "ETB",
                "EUR",
                "GBP"
            )
            .optional(),

    receivedRate:
        Joi.number()
            .greater(0)
            .allow(null, "")
            .optional(),

    receivedRateDate:
        Joi.date()
            .allow(null, "")
            .optional(),


    donationDate:
        Joi.date()
            .optional(),


    financialYear:
        Joi.string()
            .trim()
            .allow(null, "")
            .optional(),


    fundingSource:
        Joi.string()
            .valid(
                "Grant",
                "Donation",
                "Government Funding",
                "Corporate CSR",
                "Internal",
                "Other"
            )
            .optional(),


    fundingRestriction:
        Joi.string()
            .valid(
                "Restricted",
                "Unrestricted"
            )
            .optional(),


    donationType:
        Joi.string()
            .valid(
                "Cash",
                "Bank Transfer",
                "Material",
                "Equipment",
                "Service",
                "Other"
            )
            .optional(),


    status:
        Joi.string()
            .valid(
                "Pledged",
                "Received",
                "Cancelled"
            )
            .optional(),


    receiptNumber:
        Joi.string()
            .trim()
            .allow(null, "")
            .optional(),


    referenceNumber:
        Joi.string()
            .trim()
            .allow(null, "")
            .optional(),


    description:
        Joi.string()
            .trim()
            .allow(null, "")
            .optional()

});


// ==========================================
// EXPORT
// ==========================================

module.exports = {

    createDonationSchema,

    updateDonationSchema

};