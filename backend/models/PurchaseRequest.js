const mongoose = require("mongoose");

const {
    BUDGET_CATEGORIES
} = require("./Budget");


// =====================================================
// PURCHASE REQUEST (procurement)
// =====================================================
//
// A request to buy goods or services for a project, with
// the items and their estimated prices, charged to ONE line
// of an APPROVED project budget. The fiscal year comes from
// the request date (calendar year).
//
//   Draft -> Submitted -> Approved
//               |-> Returned (comment) -> edit -> Submitted
//               |-> Rejected (reason)  final
//   Approved -> Cancelled (reason)     releases the money
//
// An Approved request reserves its estimate on the budget
// line as "Committed": Remaining = Budget - Committed - Spent.
// A request cannot be submitted or approved for more than
// the line has left.
//
// Amounts: item prices are in the request currency;
// `budgetAmount` = estimatedTotal x exchangeRate, in the
// budget's currency, and is what is committed.
//
// After approval, `sourcing` holds the quotations and the
// bid analysis (services/sourcingService.js). When the
// purchase order is issued the request becomes Ordered and
// the order's total is committed instead of the estimate.
//
// =====================================================

const PURCHASE_REQUEST_STATUS = {
    DRAFT: "Draft",
    SUBMITTED: "Submitted",
    APPROVED: "Approved",
    RETURNED: "Returned",
    REJECTED: "Rejected",
    CANCELLED: "Cancelled",
    ORDERED: "Ordered",
    // its purchase order is closed (received and paid)
    CLOSED: "Closed"
};

// the bid analysis of an approved request
const SOURCING_STATUS = {
    DRAFT: "Draft",
    SUBMITTED: "Submitted",
    APPROVED: "Approved",
    RETURNED: "Returned"
};

const PROCUREMENT_METHODS = ["direct", "rfq", "tender"];

// the statuses whose estimate is reserved on the budget line
const COMMITTING_STATUSES = [
    PURCHASE_REQUEST_STATUS.APPROVED
];


const itemSchema =
    new mongoose.Schema(
        {
            description: { type: String, trim: true, required: true },
            specification: { type: String, trim: true, default: "" },
            unit: { type: String, trim: true, default: "pcs" },
            quantity: { type: Number, required: true, min: 0 },
            unitPrice: { type: Number, required: true, min: 0 },
            total: { type: Number, required: true, min: 0 }
        }
    );


// ---------------------------------------------------------------- quotations and bid analysis

const quoteItemSchema =
    new mongoose.Schema(
        {
            item: { type: mongoose.Schema.Types.ObjectId, required: true },
            unitPrice: { type: Number, required: true, min: 0 },
            total: { type: Number, required: true, min: 0 }
        },
        { _id: false }
    );

const quoteSchema =
    new mongoose.Schema(
        {
            supplier: { type: mongoose.Schema.Types.ObjectId, ref: "Supplier", required: true },
            reference: { type: String, trim: true, default: "" },
            quoteDate: { type: Date, default: null },
            validUntil: { type: Date, default: null },
            deliveryDays: { type: Number, min: 0, default: null },
            items: { type: [quoteItemSchema], default: [] },
            // in the request's currency
            total: { type: Number, required: true, min: 0 },
            notes: { type: String, trim: true, default: "" },
            enteredBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
            enteredAt: { type: Date, default: Date.now }
        }
    );

const panelSchema =
    new mongoose.Schema(
        {
            user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
            role: { type: String, default: "Member" },
            // "Approve" | "Object" | null (not yet)
            decision: { type: String, enum: ["Approve", "Object"], default: null },
            comment: { type: String, default: "" },
            at: { type: Date, default: null }
        },
        { _id: false }
    );

const sourcingSchema =
    new mongoose.Schema(
        {
            method: { type: String, enum: PROCUREMENT_METHODS, required: true },
            methodName: { type: String, default: "" },
            minQuotes: { type: Number, min: 1, default: 1 },
            needsCommittee: { type: Boolean, default: false },
            // the request's value in ETB that decided the method
            etbValue: { type: Number, min: 0, default: 0 },

            quotes: { type: [quoteSchema], default: [] },

            selectedQuote: { type: mongoose.Schema.Types.ObjectId, default: null },
            // needed when the selected quote is not the lowest
            selectionReason: { type: String, trim: true, default: "" },
            // needed when there are fewer quotes than the method asks for
            fewerQuotesReason: { type: String, trim: true, default: "" },

            committee: { type: mongoose.Schema.Types.ObjectId, ref: "ProcurementCommittee", default: null },
            committeeName: { type: String, default: "" },
            approvalsNeeded: { type: Number, default: 0 },
            panel: { type: [panelSchema], default: [] },

            status: { type: String, enum: Object.values(SOURCING_STATUS), default: SOURCING_STATUS.DRAFT },
            reviewComment: { type: String, default: "" },

            startedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
            startedAt: { type: Date, default: null },
            submittedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
            submittedAt: { type: Date, default: null },
            approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
            approvedAt: { type: Date, default: null }
        },
        { _id: false }
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


const PurchaseRequestSchema =
    new mongoose.Schema(
        {
            organization: {
                type: mongoose.Schema.Types.ObjectId,
                ref: "Organization",
                required: true,
                index: true
            },

            requestCode: { type: String, trim: true },

            // Charged to
            budget: { type: mongoose.Schema.Types.ObjectId, ref: "Budget", required: true },
            budgetLine: { type: mongoose.Schema.Types.ObjectId, required: true },
            category: { type: String, enum: BUDGET_CATEGORIES, required: true },
            program: { type: mongoose.Schema.Types.ObjectId, ref: "Program", required: true },
            project: { type: mongoose.Schema.Types.ObjectId, ref: "Project", required: true },

            requestDate: { type: Date, required: true },
            fiscalYear: { type: Number, required: true },
            neededBy: { type: Date, default: null },

            title: { type: String, trim: true, required: true },
            justification: { type: String, trim: true, default: "" },
            deliveryLocation: { type: String, trim: true, default: "" },

            items: { type: [itemSchema], default: [] },

            currency: { type: String, uppercase: true, trim: true, default: "ETB", match: /^[A-Z]{3}$/ },
            exchangeRate: { type: Number, default: 1, min: 0 },
            estimatedTotal: { type: Number, required: true, min: 0 },
            budgetCurrency: { type: String, uppercase: true, trim: true, default: "ETB" },
            budgetAmount: { type: Number, required: true, min: 0 },

            // Optional links
            activity: { type: mongoose.Schema.Types.ObjectId, ref: "Activity", default: null },
            suggestedSupplier: { type: mongoose.Schema.Types.ObjectId, ref: "Supplier", default: null },

            status: {
                type: String,
                enum: Object.values(PURCHASE_REQUEST_STATUS),
                default: PURCHASE_REQUEST_STATUS.DRAFT
            },

            reviewComment: { type: String, default: "" },

            // quotations and bid analysis (after approval)
            sourcing: { type: sourcingSchema, default: null },

            // the issued purchase order (status Ordered)
            purchaseOrder: { type: mongoose.Schema.Types.ObjectId, ref: "PurchaseOrder", default: null },

            submittedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
            submittedAt: { type: Date, default: null },
            approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
            approvedAt: { type: Date, default: null },
            rejectedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
            rejectedAt: { type: Date, default: null },
            cancelledBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
            cancelledAt: { type: Date, default: null },
            cancelReason: { type: String, default: "" },

            history: { type: [historySchema], default: [] },

            createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
            updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },

            isDeleted: { type: Boolean, default: false },
            deletedAt: { type: Date, default: null },
            deletedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null }
        },
        {
            timestamps: true
        }
    );


// Committed per budget line and year
PurchaseRequestSchema.index({ organization: 1, budget: 1, budgetLine: 1, fiscalYear: 1, status: 1 });

PurchaseRequestSchema.index({ organization: 1, isDeleted: 1, status: 1, requestDate: -1 });


// dates that must make sense (see plugins/dateRules)
PurchaseRequestSchema.plugin(
    require("./plugins/dateRules"),
    {
        what: "This purchase request",
        labels: { requestDate: "request date", neededBy: "needed-by date" },
        rules: [
            { notFuture: "requestDate", because: "Date the request on the day it is made." },
            { order: ["requestDate", "neededBy"] }
        ]
    }
);


// what the status of its parents allows (see plugins/statusRules)
PurchaseRequestSchema.plugin(
    require("./plugins/statusRules"),
    { what: "This purchase request", parents: [{ ref: "project", model: "Project", label: "project", kind: "plan" }, { ref: "activity", model: "Activity", label: "activity", kind: "plan" }] }
);


module.exports =
    mongoose.models.PurchaseRequest ||
    mongoose.model("PurchaseRequest", PurchaseRequestSchema);

module.exports.PURCHASE_REQUEST_STATUS = PURCHASE_REQUEST_STATUS;
module.exports.COMMITTING_STATUSES = COMMITTING_STATUSES;
module.exports.SOURCING_STATUS = SOURCING_STATUS;
module.exports.PROCUREMENT_METHODS = PROCUREMENT_METHODS;
