// =====================================================
// MOVING A PROJECT / ACTIVITY TO ANOTHER PARENT
// =====================================================
//
// Budgets, donations, expenses, service deliveries,
// activity runs, attendance and TORs keep the program /
// project they were recorded under. Moving a project to
// another program (or an activity to another project)
// would leave those records under the old parent, or
// silently carry their history over to the new one.
//
// So a project / activity may change its parent only while
// nothing is recorded under it yet. After that the move is
// refused with what is recorded; the way to go is a new
// project / activity under the other parent.
//
// Found from the models themselves: every model that
// stores both the child and its parent (e.g. project and
// program) counts.
//
// =====================================================

const mongoose = require("mongoose");

const ApiError = require("../utils/apiError");


const LABELS = {
    ActivityRun: ["activity run", "activity runs"],
    Attendance: ["attendance session", "attendance sessions"],
    AttendanceRecord: ["attendance record", "attendance records"],
    Budget: ["budget", "budgets"],
    Donation: ["donation", "donations"],
    Expense: ["expense", "expenses"],
    ServiceDelivery: ["service delivery", "service deliveries"],
    TermsOfReference: ["terms of reference", "terms of reference"]
};

const labelOf = (name, count) => {
    const [one, many] = LABELS[name] || [name, `${name} records`];
    return `${count} ${count === 1 ? one : many}`;
};


// What is recorded under this child with its current parent
const recordedUnder = async (childKey, parentKey, childId, organizationId) => {

    const found = [];

    for (const name of mongoose.modelNames()) {

        const model = mongoose.model(name);
        const schema = model.schema;

        if (!schema.path(childKey) || !schema.path(parentKey)) continue;

        const filter = { [childKey]: childId };
        if (schema.path("organization")) filter.organization = organizationId;
        if (schema.path("isDeleted")) filter.isDeleted = { $ne: true };

        const count = await model.countDocuments(filter);
        if (count > 0) found.push(labelOf(name, count));

    }

    return found;

};


const assertCanMove = async ({ childKey, parentKey, childId, organizationId, childLabel, parentLabel }) => {

    const found = await recordedUnder(childKey, parentKey, childId, organizationId);

    if (!found.length) return;

    throw new ApiError(
        `This ${childLabel} cannot move to another ${parentLabel}: ${found.join(", ")} ${found.length === 1 && /^1 /.test(found[0]) ? "is" : "are"} already recorded under its current ${parentLabel}, and would be left there (or have their history moved). Create a new ${childLabel} under the other ${parentLabel} instead.`,
        409
    );

};


module.exports = {
    assertProjectCanChangeProgram: (projectId, organizationId) =>
        assertCanMove({ childKey: "project", parentKey: "program", childId: projectId, organizationId, childLabel: "project", parentLabel: "program" }),
    assertActivityCanChangeProject: (activityId, organizationId) =>
        assertCanMove({ childKey: "activity", parentKey: "project", childId: activityId, organizationId, childLabel: "activity", parentLabel: "project" })
};
