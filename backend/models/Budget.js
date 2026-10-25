const mongoose = require("mongoose");


// =====================================================
// BUDGET (MASTER BUDGET)
// =====================================================
//
// Two levels:
//
//   program budget  - the envelope: an amount per fiscal
//                     year (yearlyAmounts)
//   project budget  - detailed: budget lines (category +
//                     description) with an amount per
//                     fiscal year; draws on its program's
//                     budget, which cannot be over-allocated
//
// Fiscal year = calendar year (utils/fiscalYear.js).
//
// Money columns everywhere follow
//     Remaining = Budget - Committed - Spent
// Spent comes from expenses / service deliveries and
// Committed from purchase orders (procurement, later);
// both are computed, never stored here.
//
// One active budget per program and per project.
// Approved budgets are locked; changes will go through a
// revision (version) later.
//
// =====================================================

const BUDGET_STATUS = {
    DRAFT: "Draft",
    SUBMITTED: "Submitted",
    APPROVED: "Approved",
    RETURNED: "Returned"
};


const BUDGET_LEVEL = {
    PROGRAM: "program",
    PROJECT: "project"
};


// Same categories will be used by expenses, so plan and
// actual compare line by line.

const BUDGET_CATEGORIES = [
    "Personnel",
    "Training & Workshops",
    "Travel & Per Diem",
    "Direct Beneficiary Support",
    "Supplies & Materials",
    "Equipment",
    "Consultancy & Services",
    "Administration & Overhead",
    "Other"
];


const yearAmountSchema =
    new mongoose.Schema(
        {
            fiscalYear: {
                type: Number,
                required: true
            },
            amount: {
                type: Number,
                default: 0,
                min: 0
            }
        },
        {
            _id: false
        }
    );


const budgetLineSchema =
    new mongoose.Schema(
        {
            category: {
                type: String,
                enum: BUDGET_CATEGORIES,
                required: true
            },
            description: {
                type: String,
                trim: true,
                default: ""
            },
            amounts: {
                type: [yearAmountSchema],
                default: []
            },
            total: {
                type: Number,
                default: 0
            }
        }
    );


const historySchema =
    new mongoose.Schema(
        {
            action: String,
            status: String,
            comment: {
                type: String,
                default: ""
            },
            by: {
                type: mongoose.Schema.Types.ObjectId,
                ref: "User"
            },
            at: {
                type: Date,
                default: Date.now
            }
        },
        {
            _id: false
        }
    );


// =====================================================
// REVISIONS
// =====================================================
//
// An approved budget is changed through a revision, kept
// on the same record so expenses stay linked to their
// lines (line _ids are kept):
//
//   revision  - the proposed figures while they are
//               prepared / reviewed (Draft / Submitted /
//               Returned). The approved figures stay in
//               force meanwhile.
//   versions  - the figures each approved version had,
//               saved when a revision replaces them.
//
// =====================================================

const REVISION_STATUS = {
    DRAFT: "Draft",
    SUBMITTED: "Submitted",
    RETURNED: "Returned"
};

const revisionSchema =
    new mongoose.Schema(
        {
            status: { type: String, enum: Object.values(REVISION_STATUS), default: REVISION_STATUS.DRAFT },
            reason: { type: String, trim: true, default: "" },
            reviewComment: { type: String, default: "" },
            startYear: { type: Number, required: true },
            endYear: { type: Number, required: true },
            yearlyAmounts: { type: [yearAmountSchema], default: [] },
            lines: { type: [budgetLineSchema], default: [] },
            totalAmount: { type: Number, default: 0 },
            requestedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
            requestedAt: { type: Date, default: null },
            submittedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
            submittedAt: { type: Date, default: null }
        },
        { _id: false }
    );

const versionSchema =
    new mongoose.Schema(
        {
            version: Number,
            startYear: Number,
            endYear: Number,
            yearlyAmounts: { type: [yearAmountSchema], default: [] },
            lines: { type: [budgetLineSchema], default: [] },
            totalAmount: Number,
            approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
            approvedAt: { type: Date, default: null },
            // when the next version replaced it, and why
            replacedAt: { type: Date, default: null },
            replacedBecause: { type: String, default: "" }
        },
        { _id: false }
    );


const BudgetSchema =
    new mongoose.Schema(
        {
            organization: {
                type: mongoose.Schema.Types.ObjectId,
                ref: "Organization",
                required: true,
                index: true
            },

            budgetCode: {
                type: String,
                trim: true
            },

            name: {
                type: String,
                trim: true,
                required: true
            },

            description: {
                type: String,
                trim: true,
                default: ""
            },

            level: {
                type: String,
                enum: Object.values(BUDGET_LEVEL),
                required: true
            },

            program: {
                type: mongoose.Schema.Types.ObjectId,
                ref: "Program",
                required: true
            },

            project: {
                type: mongoose.Schema.Types.ObjectId,
                ref: "Project",
                default: null
            },

            currency: {
                type: String,
                uppercase: true,
                trim: true,
                default: "ETB",
                match: /^[A-Z]{3}$/
            },

            // A project budget in another currency than its
            // program budget: 1 unit of this budget's currency =
            // rate units of the program budget's, as of date.
            // The program ceiling is checked in its currency;
            // this budget's own amounts stay as entered.
            programExchangeRate: {
                rate: { type: Number, min: 0 },
                date: { type: Date }
            },

            startYear: {
                type: Number,
                required: true
            },

            endYear: {
                type: Number,
                required: true
            },

            // Program level
            yearlyAmounts: {
                type: [yearAmountSchema],
                default: []
            },

            // Project level
            lines: {
                type: [budgetLineSchema],
                default: []
            },

            totalAmount: {
                type: Number,
                default: 0
            },

            status: {
                type: String,
                enum: Object.values(BUDGET_STATUS),
                default: BUDGET_STATUS.DRAFT
            },

            version: {
                type: Number,
                default: 1
            },

            // Bumped inside the transaction that approves or
            // voids an expense on this budget, so two approvals
            // at the same moment conflict (one is retried and
            // sees the other's amount) instead of both passing
            // the remaining-budget check.
            chargeVersion: {
                type: Number,
                default: 0
            },

            reviewComment: {
                type: String,
                default: ""
            },

            submittedBy: {
                type: mongoose.Schema.Types.ObjectId,
                ref: "User",
                default: null
            },
            submittedAt: {
                type: Date,
                default: null
            },
            approvedBy: {
                type: mongoose.Schema.Types.ObjectId,
                ref: "User",
                default: null
            },
            approvedAt: {
                type: Date,
                default: null
            },

            history: {
                type: [historySchema],
                default: []
            },

            // Pending change to an approved budget (see REVISIONS)
            revision: {
                type: revisionSchema,
                default: null
            },

            // Earlier approved versions
            versions: {
                type: [versionSchema],
                default: []
            },

            createdBy: {
                type: mongoose.Schema.Types.ObjectId,
                ref: "User",
                default: null
            },
            updatedBy: {
                type: mongoose.Schema.Types.ObjectId,
                ref: "User",
                default: null
            },

            isDeleted: {
                type: Boolean,
                default: false
            },
            deletedAt: {
                type: Date,
                default: null
            },
            deletedBy: {
                type: mongoose.Schema.Types.ObjectId,
                ref: "User",
                default: null
            }
        },
        {
            timestamps: true
        }
    );


// One active budget per program and per project

BudgetSchema.index(
    { organization: 1, program: 1 },
    {
        unique: true,
        partialFilterExpression: { level: BUDGET_LEVEL.PROGRAM, isDeleted: false }
    }
);

BudgetSchema.index(
    { organization: 1, project: 1 },
    {
        unique: true,
        partialFilterExpression: { level: BUDGET_LEVEL.PROJECT, isDeleted: false }
    }
);

BudgetSchema.index({ organization: 1, isDeleted: 1, level: 1, status: 1 });


// what the status of its parents allows (see plugins/statusRules)
BudgetSchema.plugin(
    require("./plugins/statusRules"),
    { what: "This budget", parents: [{ ref: "program", model: "Program", label: "program", kind: "plan" }, { ref: "project", model: "Project", label: "project", kind: "plan" }] }
);


module.exports =
    mongoose.models.Budget ||
    mongoose.model("Budget", BudgetSchema);

module.exports.BUDGET_STATUS = BUDGET_STATUS;
module.exports.BUDGET_LEVEL = BUDGET_LEVEL;
module.exports.BUDGET_CATEGORIES = BUDGET_CATEGORIES;
module.exports.REVISION_STATUS = REVISION_STATUS;
