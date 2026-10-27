const Joi = require("joi");

const { CURRENCY_CODES } = require("../config/currencies");

const {
    SUPPLIER_STATUS,
    SUPPLIER_CATEGORIES
} = require("../models/Supplier");


// =====================================================
// PROCUREMENT VALIDATORS (suppliers, purchase requests)
// =====================================================
//
// Status, category, fiscal year, item totals and the
// budget-currency amount of a purchase request are never
// accepted: they come from the workflow, the budget line,
// the date, the items and the exchange rate.
//
// =====================================================

const objectId =
    Joi.string()
        .pattern(/^[0-9a-fA-F]{24}$/)
        .messages({ "string.pattern.base": "{{#label}} must be a valid id." });

const optionalId = objectId.allow("", null);

const text = (max) => Joi.string().trim().allow("").max(max);


// ---------------------------------------------------------------- suppliers

const supplierFields = {
    name: Joi.string().trim().min(2).max(200),
    categories: Joi.array().items(Joi.string().valid(...SUPPLIER_CATEGORIES)).unique(),
    supplies: text(500),
    tin: text(50),
    vatRegistered: Joi.boolean(),
    licenseNumber: text(100),
    contactPerson: text(200),
    phone: text(50),
    email: Joi.string().trim().allow("").email({ tlds: { allow: false } }).max(200),
    address: text(500),
    bankName: text(200),
    bankAccountName: text(200),
    bankAccountNumber: text(100),
    status: Joi.string().valid(...Object.values(SUPPLIER_STATUS)),
    statusReason: text(1000),
    notes: text(2000)
};

const createSupplierSchema =
    Joi.object({ ...supplierFields, name: supplierFields.name.required() });

const updateSupplierSchema =
    Joi.object(supplierFields).min(1);


// ---------------------------------------------------------------- purchase requests

const item =
    Joi.object({
        _id: Joi.any().strip(),
        total: Joi.any().strip(),
        description: Joi.string().trim().min(2).max(300).required(),
        specification: text(1000),
        unit: text(30),
        quantity: Joi.number().greater(0).required(),
        unitPrice: Joi.number().greater(0).required()
    });

const requestFields = {
    budget: objectId,
    budgetLine: objectId,
    requestDate: Joi.date(),
    neededBy: Joi.date().allow(null, ""),
    title: Joi.string().trim().min(3).max(300),
    justification: text(2000),
    deliveryLocation: text(300),
    items: Joi.array().items(item).min(1).messages({ "array.min": "Add at least one item." }),
    currency: Joi.string().trim().uppercase().valid(...CURRENCY_CODES)
        .messages({ "any.only": `Currency must be one of ${CURRENCY_CODES.join(", ")}.` }),
    exchangeRate: Joi.number().greater(0).allow(null),
    activity: optionalId,
    suggestedSupplier: optionalId
};

const createPurchaseRequestSchema =
    Joi.object({
        ...requestFields,
        budget: requestFields.budget.required(),
        budgetLine: requestFields.budgetLine.required(),
        requestDate: requestFields.requestDate.required(),
        title: requestFields.title.required(),
        items: requestFields.items.required()
    });

const updatePurchaseRequestSchema =
    Joi.object(requestFields).min(1);

const approvePurchaseRequestSchema =
    Joi.object({
        comment: Joi.string().trim().allow("").max(1000)
    });

const reasonSchema = (message) =>
    Joi.object({
        comment: Joi.string().trim().min(3).max(1000).required()
            .messages({ "any.required": message, "string.min": message, "string.empty": message })
    });


module.exports = {
    createSupplierSchema,
    updateSupplierSchema,
    createPurchaseRequestSchema,
    updatePurchaseRequestSchema,
    approvePurchaseRequestSchema,
    returnPurchaseRequestSchema: reasonSchema("Say what needs to change."),
    rejectPurchaseRequestSchema: reasonSchema("Give the reason for rejecting this request."),
    cancelPurchaseRequestSchema: reasonSchema("Give the reason for cancelling this request.")
};
