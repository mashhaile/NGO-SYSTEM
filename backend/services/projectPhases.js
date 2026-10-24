// =====================================================
// PROJECT PHASES
// =====================================================
//
// A project may run in phases (Phase 1 in 2026, Phase 2 in
// 2027 ...). Each phase is a project of its own, linked to
// the main project (parentProject): it has its own budget,
// donations, activities, deliveries, expenses and reports,
// exactly like a project without phases. The main project
// groups them and shows the totals across its phases.
//
// RULES
//   - one level: a phase cannot have phases, and a project
//     that has phases cannot become a phase
//   - a phase is in its main project's program
//   - a phase lies inside its main project's dates, and
//     phases of one project do not overlap
//   - once a project has phases, new work (activities,
//     budgets, service deliveries) is recorded on a phase
//   - a donation for the main project may pay for any of
//     its phases (see donationFunding)
//
// =====================================================

const mongoose = require("mongoose");

const Project = require("../models/Project");
const ApiError = require("../utils/apiError");


const toId = (value) => String(value?._id || value || "");

const day = (value) => (value ? new Date(value).toISOString().slice(0, 10) : "");

const dateText = (value) => (value ? new Date(value).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" }) : "");


const notDeleted = (organizationId, extra = {}) => ({ organization: organizationId, isDeleted: false, ...extra });


// The main project a phase belongs to (checked)
const resolveParent = async (parentProject, organizationId, { selfId = null } = {}) => {

    if (parentProject === undefined || parentProject === null || parentProject === "") return null;

    if (!mongoose.isValidObjectId(parentProject)) throw new ApiError("Invalid main project.", 400);

    if (selfId && toId(parentProject) === toId(selfId)) throw new ApiError("A project cannot be a phase of itself.", 400);

    const parent = await Project.findOne(notDeleted(organizationId, { _id: parentProject })).lean();

    if (!parent) throw new ApiError("Main project not found.", 404);

    if (parent.parentProject) {
        throw new ApiError(`${parent.name} is itself a phase. Phases belong to the main project, not to another phase.`, 400);
    }

    if (selfId && (await Project.exists(notDeleted(organizationId, { parentProject: selfId })))) {
        throw new ApiError("This project has phases of its own, so it cannot become a phase of another project.", 400);
    }

    return parent;

};


// A phase inside its main project's dates, not overlapping another phase
const checkPhaseDates = async ({ parent, startDate, endDate, selfId = null, organizationId }) => {

    const start = new Date(startDate);
    const end = new Date(endDate);

    if (start > end) throw new ApiError("The phase ends before it starts.", 400);

    if (start < new Date(parent.startDate) || end > new Date(parent.endDate)) {
        throw new ApiError(
            `A phase must lie inside its main project's dates (${dateText(parent.startDate)} to ${dateText(parent.endDate)}).`,
            400
        );
    }

    const overlapping =
        await Project.findOne(notDeleted(organizationId, {
            parentProject: parent._id,
            ...(selfId ? { _id: { $ne: selfId } } : {}),
            startDate: { $lte: end },
            endDate: { $gte: start }
        }))
            .select("name phaseNumber startDate endDate")
            .lean();

    if (overlapping) {
        throw new ApiError(
            `This phase overlaps ${overlapping.name} (Phase ${overlapping.phaseNumber}, ${dateText(overlapping.startDate)} to ${dateText(overlapping.endDate)}). Phases of one project follow each other.`,
            400
        );
    }

};


const nextPhaseNumber = async (parentId, organizationId) => {

    const last = await Project.findOne(notDeleted(organizationId, { parentProject: parentId })).sort({ phaseNumber: -1 }).select("phaseNumber").lean();

    return Number(last?.phaseNumber || 0) + 1;

};


// A main project's new dates must still hold its phases
const assertCoversPhases = async (project, organizationId) => {

    const phases = await Project.find(notDeleted(organizationId, { parentProject: project._id })).select("name startDate endDate").lean();

    const outside = phases.find(phase => new Date(phase.startDate) < new Date(project.startDate) || new Date(phase.endDate) > new Date(project.endDate));

    if (outside) {
        throw new ApiError(
            `${outside.name} runs from ${dateText(outside.startDate)} to ${dateText(outside.endDate)}, outside these dates. A main project's dates must hold all its phases.`,
            400
        );
    }

};


// New work goes on a phase once a project has phases
const assertNotMainProject = async (projectId, organizationId, what = "This") => {

    if (!projectId || !mongoose.isValidObjectId(projectId)) return;

    const phases = await Project.find(notDeleted(organizationId, { parentProject: projectId })).select("name phaseNumber").sort({ phaseNumber: 1 }).lean();

    if (!phases.length) return;

    throw new ApiError(
        `This project runs in phases: record ${what.toLowerCase()} on the phase it belongs to (${phases.map(phase => `Phase ${phase.phaseNumber}: ${phase.name}`).join(", ")}).`,
        400
    );

};


// The phases of a project (empty for a project without phases)
const phasesOf = (projectId, organizationId) =>
    Project.find(notDeleted(organizationId, { parentProject: projectId }))
        .select("projectCode name status startDate endDate phaseNumber parentProject")
        .sort({ phaseNumber: 1 })
        .lean();


// A project and its phases (for reports and filters)
const projectAndPhases = async (projectId, organizationId) => {

    if (!mongoose.isValidObjectId(projectId)) return [];

    const phases = await Project.find(notDeleted(organizationId, { parentProject: projectId })).select("_id").lean();

    return [new mongoose.Types.ObjectId(String(projectId)), ...phases.map(phase => phase._id)];

};


// The main project of a project, if it is a phase
const parentOf = async (projectId) => {

    if (!projectId || !mongoose.isValidObjectId(projectId)) return null;

    const project = await Project.findById(projectId).select("parentProject").lean();

    return project?.parentProject ? toId(project.parentProject) : null;

};


module.exports = {
    resolveParent,
    checkPhaseDates,
    nextPhaseNumber,
    assertCoversPhases,
    assertNotMainProject,
    phasesOf,
    projectAndPhases,
    parentOf,
    day
};
