// =====================================================
// STATUSES
// =====================================================
//
// One lifecycle for the work of an organization (programs,
// projects and their phases, activities, activity runs):
//
//   Planned   -> Active -> Completed
//                 |  ^
//                 v  |
//              Suspended            Cancelled (from any)
//
// The values are fixed (rules and reports depend on them);
// an organization may show them with its own words
// (Settings > Wording).
//
// Older values are still accepted and read as their new
// ones: a project's "Draft" is Planned, an activity's
// "Ongoing" is Active.
//
// =====================================================

const WORK_STATUS = {
    PLANNED: "Planned",
    ACTIVE: "Active",
    SUSPENDED: "Suspended",
    COMPLETED: "Completed",
    CANCELLED: "Cancelled"
};

const WORK_STATUSES = Object.values(WORK_STATUS);

const LEGACY_WORK_STATUS = {
    Draft: WORK_STATUS.PLANNED,
    Ongoing: WORK_STATUS.ACTIVE
};

// what forms may send (old values included)
const WORK_STATUS_INPUT = [...WORK_STATUSES, ...Object.keys(LEGACY_WORK_STATUS)];

const toWorkStatus = (value) =>
    LEGACY_WORK_STATUS[value] || value;

// the schema field every work record uses
const workStatusField = () => ({
    type: String,
    enum: WORK_STATUSES,
    default: WORK_STATUS.PLANNED,
    set: toWorkStatus
});


// Records that are just on or off (beneficiaries, donors,
// enterprises, members)
const RECORD_STATUS = {
    ACTIVE: "Active",
    INACTIVE: "Inactive"
};


module.exports = {
    WORK_STATUS,
    WORK_STATUSES,
    WORK_STATUS_INPUT,
    LEGACY_WORK_STATUS,
    toWorkStatus,
    workStatusField,
    RECORD_STATUS
};
