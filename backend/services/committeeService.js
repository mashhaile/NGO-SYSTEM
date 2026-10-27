const mongoose = require("mongoose");

const ProcurementCommittee = require("../models/ProcurementCommittee");

const {
    COMMITTEE_ROLES,
    COMMITTEE_STATUS
} = require("../models/ProcurementCommittee");

const User = require("../models/user");

const ApiError = require("../utils/apiError");

const escapeRegex = require("../utils/escapeRegex");


// =====================================================
// PROCUREMENT COMMITTEES
// =====================================================
//
// - A name is used once per organization (any case).
// - Members are active users of the organization, each
//   once, with a role (Chair, Member, Secretary).
// - approvalsNeeded is 1 .. the number of members; empty:
//   a majority.
// - A committee with a bid analysis waiting for it is not
//   deleted or set Inactive.
//
// =====================================================

const notFound = () => new ApiError("Committee not found.", 404);

const majority = (count) => Math.floor(count / 2) + 1;


const findCommittee = async (id, organizationId) => {

    if (!mongoose.isValidObjectId(id)) throw notFound();

    const committee = await ProcurementCommittee.findOne({ _id: id, organization: organizationId, isDeleted: false });

    if (!committee) throw notFound();

    return committee;

};


const checkName = async (organizationId, name, selfId = null) => {

    const clean = String(name || "").trim();

    if (clean.length < 3) throw new ApiError("Give the committee a name.", 400);

    const taken =
        await ProcurementCommittee.findOne({
            organization: organizationId,
            isDeleted: false,
            name: { $regex: `^${escapeRegex(clean)}$`, $options: "i" },
            ...(selfId ? { _id: { $ne: selfId } } : {})
        }).select("_id").lean();

    if (taken) throw new ApiError(`A committee named "${clean}" already exists.`, 409);

    return clean;

};


const checkMembers = async (organizationId, members) => {

    if (!Array.isArray(members) || !members.length) {
        throw new ApiError("Add at least one member.", 400);
    }

    const ids = members.map(member => String(member?.user || ""));

    if (ids.some(id => !mongoose.isValidObjectId(id))) throw new ApiError("Choose each member from the users.", 400);
    if (new Set(ids).size !== ids.length) throw new ApiError("A person is in the committee only once.", 400);

    const users =
        await User.find({ _id: { $in: ids }, organization: organizationId, status: "active" }).select("_id").lean();

    if (users.length !== ids.length) {
        throw new ApiError("Every member must be an active user of the organization.", 400);
    }

    return members.map(member => ({
        user: member.user,
        role: COMMITTEE_ROLES.includes(member.role) ? member.role : "Member"
    }));

};


const checkApprovals = (value, memberCount) => {

    if (value === undefined || value === null || value === "") return majority(memberCount);

    const needed = Number(value);

    if (!Number.isInteger(needed) || needed < 1 || needed > memberCount) {
        throw new ApiError(`Approvals needed must be a whole number from 1 to ${memberCount} (the number of members).`, 400);
    }

    return needed;

};


// bid analyses waiting for this committee
const waitingFor = (organizationId, committeeId) =>
    mongoose.model("PurchaseRequest").countDocuments({
        organization: organizationId,
        isDeleted: false,
        "sourcing.committee": committeeId,
        "sourcing.status": "Submitted"
    });


// ---------------------------------------------------------------- create / update / delete

const createCommittee = async (data, organizationId, userId) => {

    const name = await checkName(organizationId, data.name);
    const members = await checkMembers(organizationId, data.members);

    const committee =
        await ProcurementCommittee.create({
            organization: organizationId,
            name,
            description: String(data.description || "").trim(),
            members,
            approvalsNeeded: checkApprovals(data.approvalsNeeded, members.length),
            status: COMMITTEE_STATUS.ACTIVE,
            createdBy: userId,
            updatedBy: userId
        });

    return getCommitteeById(committee._id, organizationId);

};


const updateCommittee = async (id, data, organizationId, userId) => {

    const committee = await findCommittee(id, organizationId);

    if (data.name !== undefined) committee.name = await checkName(organizationId, data.name, committee._id);
    if (data.description !== undefined) committee.description = String(data.description || "").trim();
    if (data.members !== undefined) committee.members = await checkMembers(organizationId, data.members);

    if (data.approvalsNeeded !== undefined || data.members !== undefined) {
        committee.approvalsNeeded =
            checkApprovals(data.approvalsNeeded ?? (data.members !== undefined ? null : committee.approvalsNeeded), committee.members.length);
    }

    if (data.status !== undefined) {
        if (!Object.values(COMMITTEE_STATUS).includes(data.status)) throw new ApiError("Unknown status.", 400);
        if (data.status === COMMITTEE_STATUS.INACTIVE && (await waitingFor(organizationId, committee._id))) {
            throw new ApiError("A bid analysis is waiting for this committee's decision. It cannot be set Inactive until it is decided.", 409);
        }
        committee.status = data.status;
    }

    committee.updatedBy = userId;

    await committee.save();

    return getCommitteeById(committee._id, organizationId);

};


const deleteCommittee = async (id, organizationId, userId) => {

    const committee = await findCommittee(id, organizationId);

    if (await waitingFor(organizationId, committee._id)) {
        throw new ApiError("A bid analysis is waiting for this committee's decision. It cannot be deleted until it is decided.", 409);
    }

    committee.isDeleted = true;
    committee.deletedAt = new Date();
    committee.deletedBy = userId;

    await committee.save();

};


// ---------------------------------------------------------------- read

const getCommittees = async (organizationId, query = {}) => {

    const filter = { organization: organizationId, isDeleted: false };

    if (query.status) filter.status = query.status;

    return ProcurementCommittee.find(filter)
        .populate("members.user", "name email role")
        .sort({ name: 1 })
        .lean();

};


const getCommitteeById = async (id, organizationId) => {

    if (!mongoose.isValidObjectId(id)) throw notFound();

    const committee =
        await ProcurementCommittee.findOne({ _id: id, organization: organizationId, isDeleted: false })
            .populate("members.user", "name email role")
            .lean();

    if (!committee) throw notFound();

    return committee;

};


// the users that can be members (active users of the organization)
const getMemberOptions = (organizationId) =>
    User.find({ organization: organizationId, status: "active" })
        .select("name email role")
        .sort({ name: 1 })
        .lean();


module.exports = {
    createCommittee,
    updateCommittee,
    deleteCommittee,
    getCommittees,
    getCommitteeById,
    getMemberOptions,
    COMMITTEE_STATUS
};
