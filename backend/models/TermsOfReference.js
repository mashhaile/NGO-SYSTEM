const mongoose = require("mongoose");


// =====================================================
// TERMS OF REFERENCE (TOR)
// =====================================================
//
// TOR for an activity / training, written in fixed
// sections and approved BEFORE the activity exists.
//
// A TOR belongs to a project. After approval the
// activity is created from it (or an existing one is
// linked), see createActivityFromTor / linkActivity.
//
// Workflow (see services/torService.js):
//
//   Draft ──submit──► Submitted ──approve──► Approved
//     ▲                   │
//     └──── Returned ◄────┘ return (with comment)
//
// Draft and Returned are editable. Submitted and
// Approved are locked.
//
// =====================================================

const TOR_STATUS = {
    DRAFT: "Draft",
    SUBMITTED: "Submitted",
    APPROVED: "Approved",
    RETURNED: "Returned"
};


// =====================================================
// BUDGET LINE
// =====================================================

const budgetLineSchema =
    new mongoose.Schema(
        {

            description: {
                type: String,
                required: true,
                trim: true
            },

            unit: {
                type: String,
                default: "",
                trim: true
            },

            quantity: {
                type: Number,
                default: 1,
                min: 0
            },

            unitCost: {
                type: Number,
                default: 0,
                min: 0
            },

            // quantity × unitCost, set by the service

            total: {
                type: Number,
                default: 0,
                min: 0
            }

        },
        {
            _id: true
        }
    );


// =====================================================
// HISTORY ENTRY (audit trail of workflow actions)
// =====================================================

const historySchema =
    new mongoose.Schema(
        {

            action: {
                type: String,
                enum: [
                    "Created",
                    "Updated",
                    "Submitted",
                    "Approved",
                    "Returned",
                    "Activity Created",
                    "Activity Linked",
                    "Activity Updated"
                ],
                required: true
            },

            status: {
                type: String,
                enum: Object.values(TOR_STATUS),
                required: true
            },

            comment: {
                type: String,
                default: "",
                trim: true
            },

            by: {
                type: mongoose.Schema.Types.ObjectId,
                ref: "User",
                default: null
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
// TOR
// =====================================================

const termsOfReferenceSchema =
    new mongoose.Schema(
        {

            organization: {
                type: mongoose.Schema.Types.ObjectId,
                ref: "Organization",
                required: true,
                index: true
            },

            torNumber: {
                type: String,
                required: true,
                trim: true
            },

            title: {
                type: String,
                required: true,
                trim: true
            },


            // -----------------------------------------
            // LINKS
            // -----------------------------------------

            project: {
                type: mongoose.Schema.Types.ObjectId,
                ref: "Project",
                required: true
            },

            // Set after approval, when the activity is
            // created from this TOR or linked.

            activity: {
                type: mongoose.Schema.Types.ObjectId,
                ref: "Activity",
                default: null
            },

            activityRun: {
                type: mongoose.Schema.Types.ObjectId,
                ref: "ActivityRun",
                default: null
            },

            // Used when the activity is created from
            // this TOR.

            activityType: {
                type: String,
                default: "Training",
                trim: true
            },


            // -----------------------------------------
            // SECTIONS
            // -----------------------------------------

            background: {
                type: String,
                default: "",
                trim: true
            },

            objectives: {
                type: String,
                default: "",
                trim: true
            },

            expectedOutputs: {
                type: String,
                default: "",
                trim: true
            },

            methodology: {
                type: String,
                default: "",
                trim: true
            },

            participants: {
                type: String,
                default: "",
                trim: true
            },

            expectedParticipants: {
                type: Number,
                default: 0,
                min: 0
            },

            facilitators: {
                type: String,
                default: "",
                trim: true
            },

            logistics: {
                type: String,
                default: "",
                trim: true
            },

            reportingRequirements: {
                type: String,
                default: "",
                trim: true
            },


            // -----------------------------------------
            // DATE AND VENUE
            // -----------------------------------------

            startDate: {
                type: Date,
                default: null
            },

            endDate: {
                type: Date,
                default: null
            },

            region: {
                type: String,
                default: "",
                trim: true
            },

            regionCode: {
                type: String,
                default: "",
                trim: true
            },

            zone: {
                type: String,
                default: "",
                trim: true
            },

            zoneCode: {
                type: String,
                default: "",
                trim: true
            },

            woreda: {
                type: String,
                default: "",
                trim: true
            },

            woredaCode: {
                type: String,
                default: "",
                trim: true
            },

            venue: {
                type: String,
                default: "",
                trim: true
            },


            // -----------------------------------------
            // BUDGET
            // -----------------------------------------

            currency: {
                type: String,
                default: "ETB",
                trim: true,
                uppercase: true
            },

            budgetLines: {
                type: [budgetLineSchema],
                default: []
            },

            totalBudget: {
                type: Number,
                default: 0,
                min: 0
            },


            // -----------------------------------------
            // WORKFLOW
            // -----------------------------------------

            status: {
                type: String,
                enum: Object.values(TOR_STATUS),
                default: TOR_STATUS.DRAFT,
                index: true
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

            // Latest return comment, shown to the author

            reviewComment: {
                type: String,
                default: "",
                trim: true
            },

            history: {
                type: [historySchema],
                default: []
            },


            // -----------------------------------------
            // AUDIT
            // -----------------------------------------

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


// =====================================================
// INDEXES
// =====================================================

termsOfReferenceSchema.index(
    {
        organization: 1,
        torNumber: 1
    },
    {
        unique: true
    }
);

termsOfReferenceSchema.index({
    organization: 1,
    activity: 1
});

termsOfReferenceSchema.index({
    organization: 1,
    project: 1
});

termsOfReferenceSchema.index({
    organization: 1,
    status: 1,
    createdAt: -1
});


// dates that must make sense (see plugins/dateRules)
termsOfReferenceSchema.plugin(
    require("./plugins/dateRules"),
    {
        what: "This TOR",
        rules: [
            { order: ["startDate", "endDate"] }
        ]
    }
);

// dated inside its project (see plugins/insideProjectDates)
termsOfReferenceSchema.plugin(
    require("./plugins/insideProjectDates"),
    { dates: ["startDate", "endDate"], what: "This TOR", labels: { startDate: "start date", endDate: "end date" } }
);


const TermsOfReference =
    mongoose.model(
        "TermsOfReference",
        termsOfReferenceSchema
    );


module.exports = TermsOfReference;

module.exports.TOR_STATUS = TOR_STATUS;
