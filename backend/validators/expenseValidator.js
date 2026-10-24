const Joi = require("joi");

const { CURRENCY_CODES } = require("../config/currencies");

// ETB, USD, EUR, GBP, CHF (config/currencies.js)
const currencyCode =
    Joi.string()
        .trim()
        .uppercase()
        .valid(...CURRENCY_CODES)
        .messages({ "any.only": `Currency must be one of ${CURRENCY_CODES.join(", ")}.` });

const {
    PAYMENT_METHODS
} = require("../models/Expense");


// =====================================================
// EXPENSE VALIDATORS
// =====================================================
//
// Status, category, fiscal year and the budget-currency
// amount are never accepted: they come from the workflow,
// the budget line, the date and the exchange rate.
//
// =====================================================

const objectId =
    Joi.string()
        .pattern(/^[0-9a-fA-F]{24}$/)
        .messages({ "string.pattern.base": "{{#label}} must be a valid id." });

const optionalId = objectId.allow("", null);

const currency =
    currencyCode;

const fields = {
    budget: objectId,
    budgetLine: objectId,
    expenseDate: Joi.date(),
    description: Joi.string().trim().min(3).max(500),
    payee: Joi.string().trim().allow("").max(200),
    referenceNumber: Joi.string().trim().allow("").max(100),
    paymentMethod: Joi.string().valid(...PAYMENT_METHODS),
    amount: Joi.number().greater(0),
    currency,
    exchangeRate: Joi.number().greater(0).allow(null),
    donation: optionalId,
    activity: optionalId
};


const createExpenseSchema =
    Joi.object({
        ...fields,
        budget: fields.budget.required(),
        budgetLine: fields.budgetLine.required(),
        expenseDate: fields.expenseDate.required(),
        description: fields.description.required(),
        amount: fields.amount.required()
    });

const updateExpenseSchema =
    Joi.object(fields).min(1);

const approveExpenseSchema =
    Joi.object({
        comment: Joi.string().trim().allow("").max(1000),
        allowOverBudget: Joi.boolean().default(false)
    });

const reasonSchema = (message) =>
    Joi.object({
        comment: Joi.string().trim().min(3).max(1000).required()
            .messages({ "any.required": message, "string.min": message, "string.empty": message })
    });

module.exports = {
    createExpenseSchema,
    updateExpenseSchema,
    approveExpenseSchema,
    returnExpenseSchema: reasonSchema("Say what needs to change."),
    voidExpenseSchema: reasonSchema("Give the reason for voiding this expense.")
};
