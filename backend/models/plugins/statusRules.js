// =====================================================
// STATUS RULES (what a status allows)
// =====================================================
//
// Work that is Cancelled or Suspended takes nothing new.
// Work that is Completed takes no new plans (projects,
// activities, runs, TORs, budgets, enrollments) but still
// takes late records of what was done (deliveries,
// attendance, expenses).
// An Inactive beneficiary, donor or enterprise takes
// nothing new either (enrollments, deliveries, donations,
// members).
//
// Checked when a record is created or moved to another
// parent; editing an existing record is not blocked.
//
//   schema.plugin(statusRules, {
//       what: "This activity",
//       parents: [{ ref: "project", model: "Project", label: "project", kind: "plan" }],
//       inactive: [{ ref: "beneficiary", model: "Beneficiary", label: "beneficiary" }]
//   });
//
// =====================================================

const mongoose = require("mongoose");

const ApiError = require("../../utils/apiError");


const nameOf = (record) =>
    record?.name || record?.title || [record?.firstName, record?.middleName, record?.lastName].filter(Boolean).join(" ") ||
    record?.projectCode || record?.programCode || record?.activityCode || record?.runCode || "";

const load = (model, id) =>
    mongoose.model(model).findById(id).select("name title firstName middleName lastName status projectCode programCode activityCode runCode").lean();


const statusRules = (schema, { what = "This record", parents = [], inactive = [] } = {}) => {

    schema.pre("validate", async function () {

        if (this.isDeleted) return;

        for (const parent of parents) {
            const id = this.get(parent.ref);
            if (!id || !(this.isNew || this.isModified(parent.ref))) continue;
            const record = await load(parent.model, id?._id || id);
            if (!record) continue;
            const status = record.status;
            if (status === "Cancelled" || status === "Suspended") {
                throw new ApiError(
                    `${what} cannot be added: the ${parent.label} ${nameOf(record)} is ${status}. Set it back to Active first if the work goes on.`,
                    400
                );
            }
            if (status === "Completed" && parent.kind === "plan") {
                throw new ApiError(
                    `${what} cannot be added: the ${parent.label} ${nameOf(record)} is Completed. Records of work done (deliveries, attendance, expenses) can still be added; new plans cannot.`,
                    400
                );
            }
        }

        for (const item of inactive) {
            const id = this.get(item.ref);
            if (!id || !(this.isNew || this.isModified(item.ref))) continue;
            const record = await load(item.model, id?._id || id);
            if (record?.status === "Inactive") {
                throw new ApiError(
                    `${what} cannot be added: the ${item.label} ${nameOf(record)} is Inactive. Make them Active first.`,
                    400
                );
            }
        }

    });

};


module.exports = statusRules;
