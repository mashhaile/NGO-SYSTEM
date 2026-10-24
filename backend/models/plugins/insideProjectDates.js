// =====================================================
// DATED INSIDE ITS PROJECT
// =====================================================
//
// Work recorded under a project (an activity, an activity
// run, a service delivery, an attendance session) happens
// between the project's start and end dates. Checked when
// the record is created and whenever its date or project
// changes, so an older record can still be edited for
// anything else.
//
//   schema.plugin(insideProjectDates, {
//       dates: ["startDate", "endDate"],
//       what: "This activity run"
//   });
//
// Donations (a grant may come before the project starts)
// and expenses (limited to their budget's years) are not
// checked here.
//
// =====================================================

const mongoose = require("mongoose");

const ApiError = require("../../utils/apiError");


const day = (value) => {
    if (!value) return null;
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date.toISOString().slice(0, 10);
};

const shown = (value) =>
    new Date(value).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" });


const check = async ({ projectId, values, what, labels }) => {

    if (!projectId || !mongoose.isValidObjectId(String(projectId?._id || projectId))) return;

    const project =
        await mongoose.model("Project")
            .findById(projectId?._id || projectId)
            .select("name startDate endDate")
            .lean();

    if (!project?.startDate || !project?.endDate) return;

    const start = day(project.startDate);
    const end = day(project.endDate);

    for (const [field, value] of Object.entries(values)) {

        const date = day(value);
        if (!date) continue;

        if (date < start || date > end) {
            throw new ApiError(
                `${what}'s ${labels[field] || field} (${shown(value)}) is outside its project's dates: ${project.name} runs from ${shown(project.startDate)} to ${shown(project.endDate)}. Choose a date inside the project, or change the project's dates first.`,
                400
            );
        }

    }

};


const insideProjectDates = (schema, { dates = [], what = "This record", labels = {} } = {}) => {

    const nice = Object.fromEntries(dates.map(field => [field, labels[field] || field.replace(/([a-z])([A-Z])/g, "$1 $2").toLowerCase()]));

    // create / save
    schema.pre("validate", async function () {

        if (this.isDeleted) return;

        const changed =
            this.isNew ||
            this.isModified("project") ||
            dates.some(field => this.isModified(field));

        if (!changed) return;

        await check({
            projectId: this.project,
            values: Object.fromEntries(dates.map(field => [field, this.get(field)])),
            what,
            labels: nice
        });

    });

    // findOneAndUpdate (e.g. editing an attendance session)
    schema.pre("findOneAndUpdate", async function () {

        const update = this.getUpdate() || {};
        const set = { ...update, ...(update.$set || {}) };

        const touched = ["project", ...dates].some(field => set[field] !== undefined);
        if (!touched || set.isDeleted === true) return;

        const current = await this.model.findOne(this.getQuery()).select(["project", ...dates].join(" ")).lean();
        if (!current) return;

        await check({
            projectId: set.project !== undefined ? set.project : current.project,
            values: Object.fromEntries(dates.map(field => [field, set[field] !== undefined ? set[field] : current[field]])),
            what,
            labels: nice
        });

    });

};


module.exports = insideProjectDates;
