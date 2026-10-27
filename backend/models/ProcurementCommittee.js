const mongoose = require("mongoose");


// =====================================================
// PROCUREMENT COMMITTEE
// =====================================================
//
// A named group of users that approves bid analyses for
// the procurement methods that need a committee (a tender,
// by default). An organization can have several (e.g. Bid
// Evaluation Committee, Tender Committee, a committee per
// office).
//
// A bid analysis sent to a committee is approved when
// `approvalsNeeded` members approve it; it goes back to the
// officer when too many object for that to happen. The
// members are copied onto the bid analysis when it is
// submitted, so changing the committee later does not
// change a decision in progress.
//
// =====================================================

const COMMITTEE_ROLES = ["Chair", "Member", "Secretary"];

const COMMITTEE_STATUS = {
    ACTIVE: "Active",
    INACTIVE: "Inactive"
};


const memberSchema =
    new mongoose.Schema(
        {
            user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
            role: { type: String, enum: COMMITTEE_ROLES, default: "Member" }
        },
        { _id: false }
    );


const ProcurementCommitteeSchema =
    new mongoose.Schema(
        {
            organization: {
                type: mongoose.Schema.Types.ObjectId,
                ref: "Organization",
                required: true,
                index: true
            },

            name: { type: String, trim: true, required: true },
            description: { type: String, trim: true, default: "" },

            members: { type: [memberSchema], default: [] },

            // how many members must approve (at most the number of members)
            approvalsNeeded: { type: Number, min: 1, default: 1 },

            status: {
                type: String,
                enum: Object.values(COMMITTEE_STATUS),
                default: COMMITTEE_STATUS.ACTIVE
            },

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


module.exports =
    mongoose.models.ProcurementCommittee ||
    mongoose.model("ProcurementCommittee", ProcurementCommitteeSchema);

module.exports.COMMITTEE_ROLES = COMMITTEE_ROLES;
module.exports.COMMITTEE_STATUS = COMMITTEE_STATUS;
