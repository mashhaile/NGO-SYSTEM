const mongoose = require("mongoose");

const {
    BUDGET_CATEGORIES
} = require("./Budget");


// =====================================================
// PURCHASE ORDER (procurement)
// =====================================================
//
// The order placed with the supplier whose quotation won
// the approved bid analysis of a purchase request, at the
// quoted prices. Charged to the same budget line as the
// request.
//
//   Issued -> Cancelled (reason)
//   (step 3: goods received and payment)
//
// An Issued order reserves its total on the budget line as
// "Committed", instead of the request's estimate. Cancelling
// it gives the request back (Approved) so another supplier
// can be chosen, or the request cancelled.
//
// =====================================================

const PURCHASE_ORDER_STATUS = {
    ISSUED: "Issued",
    CANCELLED: "Cancelled"
};

// the statuses whose total is reserved on the budget line
const PO_COMMITTING_STATUSES = [
    PURCHASE_ORDER_STATUS.ISSUED
];


const itemSchema =
    new mongoose.Schema(
        {
            // the purchase request item it orders
            requestItem: { type: mongoose.Schema.Types.ObjectId, default: null },
            description: { type: String, trim: true, required: true },
            specification: { type: String, trim: true, default: "" },
            unit: { type: String, trim: true, default: "pcs" },
            quantity: { type: Number, required: true, min: 0 },
            unitPrice: { type: Number, required: true, min: 0 },
            total: { type: Number, required: true, min: 0 }
        }
    );


const historySchema =
    new mongoose.Schema(
        {
            action: String,
            status: String,
            comment: { type: String, default: "" },
            by: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
            at: { type: Date, default: Date.now }
        },
        { _id: false }
    );


const PurchaseOrderSchema =
    new mongoose.Schema(
        {
            organization: {
                type: mongoose.Schema.Types.ObjectId,
                ref: "Organization",
                required: true,
                index: true
            },

            poCode: { type: String, trim: true },

            purchaseRequest: { type: mongoose.Schema.Types.ObjectId, ref: "PurchaseRequest", required: true },
            supplier: { type: mongoose.Schema.Types.ObjectId, ref: "Supplier", required: true },
            // the winning quotation on the request
            quote: { type: mongoose.Schema.Types.ObjectId, default: null },
            quoteReference: { type: String, trim: true, default: "" },

            // Charged to (from the request)
            budget: { type: mongoose.Schema.Types.ObjectId, ref: "Budget", required: true },
            budgetLine: { type: mongoose.Schema.Types.ObjectId, required: true },
            category: { type: String, enum: BUDGET_CATEGORIES, required: true },
            program: { type: mongoose.Schema.Types.ObjectId, ref: "Program", required: true },
            project: { type: mongoose.Schema.Types.ObjectId, ref: "Project", required: true },
            fiscalYear: { type: Number, required: true },

            orderDate: { type: Date, required: true },
            deliveryDate: { type: Date, default: null },
            deliveryLocation: { type: String, trim: true, default: "" },
            paymentTerms: { type: String, trim: true, default: "" },
            notes: { type: String, trim: true, default: "" },

            items: { type: [itemSchema], default: [] },

            currency: { type: String, uppercase: true, trim: true, default: "ETB", match: /^[A-Z]{3}$/ },
            exchangeRate: { type: Number, default: 1, min: 0 },
            total: { type: Number, required: true, min: 0 },
            budgetCurrency: { type: String, uppercase: true, trim: true, default: "ETB" },
            budgetAmount: { type: Number, required: true, min: 0 },

            status: {
                type: String,
                enum: Object.values(PURCHASE_ORDER_STATUS),
                default: PURCHASE_ORDER_STATUS.ISSUED
            },

            issuedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
            cancelledBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
            cancelledAt: { type: Date, default: null },
            cancelReason: { type: String, default: "" },

            history: { type: [historySchema], default: [] },

            createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
            updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null }
        },
        {
            timestamps: true
        }
    );


// Committed per budget line and year
PurchaseOrderSchema.index({ organization: 1, budget: 1, budgetLine: 1, fiscalYear: 1, status: 1 });

PurchaseOrderSchema.index({ organization: 1, status: 1, orderDate: -1 });


// dates that must make sense (see plugins/dateRules)
PurchaseOrderSchema.plugin(
    require("./plugins/dateRules"),
    {
        what: "This purchase order",
        labels: { orderDate: "order date", deliveryDate: "delivery date" },
        rules: [
            { notFuture: "orderDate", because: "Date the order on the day it is issued." },
            { order: ["orderDate", "deliveryDate"] }
        ]
    }
);


module.exports =
    mongoose.models.PurchaseOrder ||
    mongoose.model("PurchaseOrder", PurchaseOrderSchema);

module.exports.PURCHASE_ORDER_STATUS = PURCHASE_ORDER_STATUS;
module.exports.PO_COMMITTING_STATUSES = PO_COMMITTING_STATUSES;
