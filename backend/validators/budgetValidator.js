const Joi = require("joi");

const {
    BUDGET_LEVEL,
    BUDGET_CATEGORIES
} = require("../models/Budget");


// =====================================================
// BUDGET VALIDATORS
// =====================================================
//
// Status is never accepted: it only changes through
// submit / approve / return. Totals are computed by the
// service, so they are not accepted either.
//
// =====================================================

const objectId =
    Joi.string()
        .pattern(/^[0-9a-fA-F]{24}$/)
        .messages({ "string.pattern.base": "{{#label}} must be a valid id." });

const fiscalYear =
    Joi.number().integer().min(2000).max(2100);

const yearAmount =
    Joi.object({
        fiscalYear: fiscalYear.required(),
        amount: Joi.number().min(0).allow(null).default(0)
    });

const line =
    Joi.object({
        _id: objectId.optional(),
        category: Joi.string().valid(...BUDGET_CATEGORIES).required(),
        description: Joi.string().trim().allow("").max(300).default(""),
        amounts: Joi.array().items(yearAmount).default([])
    });

const currency =
    Joi.string()
        .trim()
        .uppercase()
        .pattern(/^[A-Z]{3}$/)
        .messages({ "string.pattern.base": "Currency must be a 3-letter code such as ETB or USD." });


// 1 unit of the budget's currency = rate of the program budget's
const exchangeRate =
    Joi.object({
        rate: Joi.number().greater(0).required()
            .messages({ "number.greater": "The exchange rate must be more than 0.", "any.required": "Enter the exchange rate." }),
        date: Joi.date().required()
            .messages({ "any.required": "Enter the date of the exchange rate." })
    }).allow(null);


const createBudgetSchema =
    Joi.object({
        level: Joi.string().valid(...Object.values(BUDGET_LEVEL)).required(),
        name: Joi.string().trim().min(3).max(150).required(),
        description: Joi.string().trim().allow("").max(2000),
        program: objectId.when("level", { is: BUDGET_LEVEL.PROGRAM, then: Joi.required(), otherwise: Joi.optional().allow("", null) }),
        project: objectId.when("level", { is: BUDGET_LEVEL.PROJECT, then: Joi.required(), otherwise: Joi.optional().allow("", null) }),
        currency: currency.default("ETB"),
        programExchangeRate: exchangeRate,
        startYear: fiscalYear.required(),
        endYear: fiscalYear.required(),
        yearlyAmounts: Joi.array().items(yearAmount).default([]),
        lines: Joi.array().items(line).max(200).default([])
    });


// Level / program / project are fixed after creation

const updateBudgetSchema =
    Joi.object({
        name: Joi.string().trim().min(3).max(150),
        description: Joi.string().trim().allow("").max(2000),
        currency,
        programExchangeRate: exchangeRate,
        startYear: fiscalYear,
        endYear: fiscalYear,
        yearlyAmounts: Joi.array().items(yearAmount),
        lines: Joi.array().items(line).max(200)
    }).min(1);


const approveBudgetSchema =
    Joi.object({
        comment: Joi.string().trim().allow("").max(1000)
    });

const returnBudgetSchema =
    Joi.object({
        comment: Joi.string().trim().min(3).max(1000).required()
            .messages({ "any.required": "Say what needs to change.", "string.min": "Say what needs to change." })
    });


// Editing a revision: same figures as an update, plus the reason

const updateRevisionSchema =
    Joi.object({
        reason: Joi.string().trim().allow("").max(1000),
        startYear: fiscalYear,
        endYear: fiscalYear,
        yearlyAmounts: Joi.array().items(yearAmount),
        lines: Joi.array().items(line).max(200)
    }).min(1);


module.exports = {
    createBudgetSchema,
    updateBudgetSchema,
    approveBudgetSchema,
    returnBudgetSchema,
    updateRevisionSchema
};
