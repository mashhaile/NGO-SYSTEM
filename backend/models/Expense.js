const mongoose = require("mongoose");

const {
    BUDGET_CATEGORIES
} = require("./Budget");


// =====================================================
// EXPENSE
// =====================================================
//
// Actual spending, charged to ONE line of an APPROVED
// project budget. The fiscal year comes from the expense
// date (calendar year).
//
//   Draft -> Submitted -> Approved
//               |-> Returned (comment) -> edit -> Submitted
//   Approved -> Voided (reason)   never deleted once approved
//
// Only Approved expenses count as Spent on the budget;
// Draft / Submitted show as "pending".
//
// Amounts: `amount` is in the expense currency;
// `budgetAmount` = amount x exchangeRate, in the budget's
// currency, and is what is charged to the line.
//
// `source` is "direct" now; "procurement" is reserved for
// payments against purchase orders (later), so the two are
// never counted twice.
//
// =====================================================

const EXPENSE_STATUS = {
    DRAFT: "Draft",
    SUBMITTED: "Submitted",
    APPROVED: "Approved",
    RETURNED: "Returned",
    VOIDED: "Voided"
};


const PAYMENT_METHODS = [
    "Cash",
    "Bank Transfer",
    "Cheque",
    "Mobile Money",
    "Other"
];


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


const ExpenseSchema =
    new mongoose.Schema(
        {
            organization: {
                type: mongoose.Schema.Types.ObjectId,
                ref: "Organization",
                required: true,
                index: true
            },

            expenseCode: { type: String, trim: true },

            // Charged to
            budget: { type: mongoose.Schema.Types.ObjectId, ref: "Budget", required: true },
            budgetLine: { type: mongoose.Schema.Types.ObjectId, required: true },
            category: { type: String, enum: BUDGET_CATEGORIES, required: true },
            program: { type: mongoose.Schema.Types.ObjectId, ref: "Program", required: true },
            project: { type: mongoose.Schema.Types.ObjectId, ref: "Project", required: true },

            expenseDate: { type: Date, required: true },
            fiscalYear: { type: Number, required: true },

            description: { type: String, trim: true, required: true },
            payee: { type: String, trim: true, default: "" },
            referenceNumber: { type: String, trim: true, default: "" },
            paymentMethod: { type: String, enum: PAYMENT_METHODS, default: "Cash" },

            amount: { type: Number, required: true, min: 0 },
            currency: { type: String, uppercase: true, trim: true, default: "ETB", match: /^[A-Z]{3}$/ },
            exchangeRate: { type: Number, default: 1, min: 0 },
            budgetCurrency: { type: String, uppercase: true, trim: true, default: "ETB" },
            budgetAmount: { type: Number, required: true, min: 0 },

            // Optional links
            donation: { type: mongoose.Schema.Types.ObjectId, ref: "Donation", default: null },
            activity: { type: mongoose.Schema.Types.ObjectId, ref: "Activity", default: null },
            activityRun: { type: mongoose.Schema.Types.ObjectId, ref: "ActivityRun", default: null },

            source: { type: String, enum: ["direct", "procurement"], default: "direct" },

            status: {
                type: String,
                enum: Object.values(EXPENSE_STATUS),
                default: EXPENSE_STATUS.DRAFT
            },

            // Set when the approver knowingly approves past the line's budget
            approvedOverBudget: { type: Boolean, default: false },

            reviewComment: { type: String, default: "" },

            submittedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
            submittedAt: { type: Date, default: null },
            approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
            approvedAt: { type: Date, default: null },
            voidedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
            voidedAt: { type: Date, default: null },
            voidReason: { type: String, default: "" },

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


// Spent per budget line and year
ExpenseSchema.index({ organization: 1, budget: 1, budgetLine: 1, fiscalYear: 1, status: 1 });

ExpenseSchema.index({ organization: 1, isDeleted: 1, status: 1, expenseDate: -1 });


// dates that must make sense (see plugins/dateRules)
ExpenseSchema.plugin(
    require("./plugins/dateRules"),
    {
        what: "This expense",
        labels: { expenseDate: "date" },
        rules: [
            { notFuture: "expenseDate", because: "Record an expense on the day it was paid." }
        ]
    }
);


// what the status of its parents allows (see plugins/statusRules)
ExpenseSchema.plugin(
    require("./plugins/statusRules"),
    { what: "This expense", parents: [{ ref: "project", model: "Project", label: "project", kind: "record" }, { ref: "activity", model: "Activity", label: "activity", kind: "record" }] }
);


module.exports =
    mongoose.models.Expense ||
    mongoose.model("Expense", ExpenseSchema);

module.exports.EXPENSE_STATUS = EXPENSE_STATUS;
module.exports.PAYMENT_METHODS = PAYMENT_METHODS;
