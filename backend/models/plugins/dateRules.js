// =====================================================
// DATE RULES
// =====================================================
//
// Dates that must make sense together, checked on the
// record itself (create, save and findOneAndUpdate), so
// every screen and import gets the same rule:
//
//   order     an end is not before its start
//   inside    a date lies inside its parent's dates (a
//             project inside its program, a session inside
//             its activity run ...)
//   notFuture something already done is not dated in the
//             future (a received donation, a delivered
//             delivery, an expense, a date of birth)
//   custom    any other check (async, returns a message)
//
// A rule runs only when one of its fields (or the parent
// link) is new or changed, so an older record can still be
// edited for anything else.
//
//   schema.plugin(dateRules, { what: "This project", rules: [
//       { order: ["startDate", "endDate"] },
//       { inside: { model: "Program", ref: "program", fields: ["startDate", "endDate"] } },
//       { notFuture: "expenseDate", when: (doc) => doc.status === "Approved" }
//   ] });
//
// Work inside its project's dates: see insideProjectDates.
//
// =====================================================

const mongoose = require("mongoose");

const ApiError = require("../../utils/apiError");


// "today" in Ethiopia (UTC+3), as YYYY-MM-DD
const today = () => new Date(Date.now() + 3 * 60 * 60 * 1000).toISOString().slice(0, 10);

const day = (value) => {
    if (!value) return null;
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date.toISOString().slice(0, 10);
};

// DD/MM/YYYY
const shown = (value) =>
    require("../../utils/dateFormat").formatDate(new Date(`${day(value)}T00:00:00Z`));

const words = (field) => field.replace(/([a-z])([A-Z])/g, "$1 $2").replace(/ time$/i, "").toLowerCase();


const fieldsOf = (rule) =>
    rule.order ? rule.order
        : rule.inside ? [rule.inside.ref, ...rule.inside.fields]
            : rule.notFuture ? [rule.notFuture, ...(rule.watch || [])]
                : rule.fields || [];


const runRule = async (rule, values, what, labels) => {

    const label = (field) => labels[field] || words(field);

    if (rule.order) {
        const [first, second] = rule.order;
        if (day(values[first]) && day(values[second]) && day(values[second]) < day(values[first])) {
            return `${what}'s ${label(second)} (${shown(values[second])}) is before its ${label(first)} (${shown(values[first])}).`;
        }
        return null;
    }

    if (rule.inside) {
        const { model, ref, fields, name = "name", title = model.toLowerCase() } = rule.inside;
        const id = values[ref]?._id || values[ref];
        if (!id || !mongoose.isValidObjectId(String(id))) return null;
        const parent = await mongoose.model(model).findById(id).select(`${name} startDate endDate`).lean();
        if (!parent?.startDate) return null;
        const start = day(parent.startDate);
        const end = parent.endDate ? day(parent.endDate) : null;
        for (const field of fields) {
            const value = day(values[field]);
            if (value && (value < start || (end && value > end))) {
                return `${what}'s ${label(field)} (${shown(value)}) is outside its ${title}'s dates: ${parent[name] || `the ${title}`} runs from ${shown(start)}${end ? ` to ${shown(end)}` : " (no end date)"}.`;
            }
        }
        return null;
    }

    if (rule.notFuture) {
        if (rule.when && !rule.when(values)) return null;
        const value = day(values[rule.notFuture]);
        if (value && value > today()) {
            return `${what}'s ${label(rule.notFuture)} (${shown(value)}) is in the future.${rule.because ? ` ${rule.because}` : ""}`;
        }
        return null;
    }

    if (rule.check) return rule.check(values);

    return null;

};


const dateRules = (schema, { what = "This record", rules = [], labels = {} } = {}) => {

    const all = [...new Set(rules.flatMap(fieldsOf))];

    const run = async (values, changed) => {
        for (const rule of rules) {
            if (!fieldsOf(rule).some(changed)) continue;
            const message = await runRule(rule, values, what, labels);
            if (message) throw new ApiError(message, 400);
        }
    };

    schema.pre("validate", async function () {
        if (this.isDeleted) return;
        await run(this.toObject({ depopulate: true }), field => this.isNew || this.isModified(field));
    });

    schema.pre("findOneAndUpdate", async function () {
        const update = this.getUpdate() || {};
        const set = { ...update, ...(update.$set || {}) };
        if (set.isDeleted === true) return;
        if (!all.some(field => set[field] !== undefined)) return;
        const current = await this.model.findOne(this.getQuery()).lean();
        if (!current) return;
        await run({ ...current, ...set }, field => set[field] !== undefined);
    });

};


module.exports = dateRules;
module.exports.today = today;
module.exports.day = day;
