// =====================================================
// STATUSES (same as backend/constants/workStatus.js)
// =====================================================
//
// One lifecycle for programs, projects (and phases),
// activities and activity runs:
//   Planned -> Active -> Completed, or Suspended / Cancelled
//
// Labels can be renamed per organization (Settings >
// Wording); the values stay.
//
// =====================================================

export const WORK_STATUSES = ["Planned", "Active", "Suspended", "Completed", "Cancelled"];

export const WORK_STATUS_OPTIONS =
    WORK_STATUSES.map(value => ({ value, label: value }));

// what a status allows, shown next to the status field
export const WORK_STATUS_HELP =
    "Suspended or Cancelled: nothing new can be added. Completed: no new plans, but late records (deliveries, attendance, expenses) can still be added.";
