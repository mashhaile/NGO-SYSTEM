// =====================================================
// ROLES (built-in + custom)
// =====================================================
//
// Built-in roles: organization_admin, finance_officer,
// data_entry, viewer (constants/rolepermissions.js), the
// same for every organization.
//
// Custom roles: each organization's own (models/Role.js),
// made by its admin: a name and a set of permissions, at
// most the organization admin's (never the platform ones:
// plans, deleting the organization). A user given a custom
// role gets exactly its permissions; their built-in role is
// kept as Viewer underneath, so anything that checks the
// built-in role sees the least access.
//
// permissionsOf(user) is the one place permissions are
// worked out (login, every request, reports, approvers).
//
// =====================================================

const mongoose = require("mongoose");

const Role = require("../models/Role");
const User = require("../models/user");
const ApiError = require("../utils/apiError");

const rolePermissions = require("../constants/rolepermissions");


const BUILT_IN = [
    { key: "organization_admin", name: "Organization Admin", description: "Everything in the organization, including users, roles and settings." },
    { key: "finance_officer", name: "Finance Officer", description: "Budgets and expenses: create, approve; reads the rest." },
    { key: "data_entry", name: "Data Entry", description: "Records beneficiaries, activities, attendance and service deliveries." },
    { key: "viewer", name: "Viewer", description: "Reads everything, changes nothing." }
];

// what a custom role may contain: the organization admin's permissions
const GRANTABLE = new Set(rolePermissions.organization_admin || []);


// ---------------------------------------------------------------- permissions of a user

const permissionsOf = async (user) => {

    if (user?.customRole && mongoose.isValidObjectId(user.customRole)) {
        const role = await Role.findOne({ _id: user.customRole, organization: user.organization, isDeleted: false }).select("permissions").lean();
        if (role) return (role.permissions || []).filter(permission => GRANTABLE.has(permission));
    }

    return rolePermissions[user?.role] || [];

};

const roleNameOf = async (user) => {
    if (user?.customRole && mongoose.isValidObjectId(user.customRole)) {
        const role = await Role.findById(user.customRole).select("name isDeleted").lean();
        if (role && !role.isDeleted) return role.name;
    }
    const replace = await require("./terminologyService").replacerFor(user?.organization);
    return replace(BUILT_IN.find(item => item.key === user?.role)?.name || user?.role || "");
};


// ---------------------------------------------------------------- the permission list, grouped (for the role screen)

const MODULES = {
    organization: "Organization", user: "Users", role: "Roles", beneficiary: "Beneficiaries", enterprise: "Enterprises",
    customfield: "Custom fields", lookup: "Lookups (lists)", program: "Programs", project: "Projects",
    service: "Service deliveries", enrollment: "Enrollments", activity: "Activities", activity_run: "Activity runs",
    tor: "Terms of reference", attendance: "Attendance sessions", attendance_record: "Attendance records",
    donor: "Donors", donation: "Donations", notification: "Notifications", report: "Reports",
    budget: "Budgets", expense: "Expenses"
};

const ACTIONS = {
    read: "View", create: "Create", update: "Edit", delete: "Delete", approve: "Approve",
    share: "Share with donors", create_activity: "Create activity from TOR", update_activity: "Link TOR to activity",
    "audit.read": "View audit log", assign_data_entry: "Give the Data Entry role", assign_viewer: "Give the Viewer role",
    assign_finance: "Give the Finance Officer role", assign_org_admin: "Give the Organization Admin role"
};

const catalog = () => {
    const groups = new Map();
    for (const permission of GRANTABLE) {
        const [module, ...rest] = permission.split(".");
        const action = rest.join(".");
        const group = groups.get(module) || { module, label: MODULES[module] || module, permissions: [] };
        group.permissions.push({ code: permission, label: ACTIONS[action] || action.replace(/_/g, " ") });
        groups.set(module, group);
    }
    return [...groups.values()];
};


// ---------------------------------------------------------------- roles of an organization

const cleanPermissions = (permissions) => {
    const list = [...new Set((Array.isArray(permissions) ? permissions : []).map(String))];
    const refused = list.filter(permission => !GRANTABLE.has(permission));
    if (refused.length) throw new ApiError(`These permissions cannot be given to a role: ${refused.join(", ")}.`, 400);
    // seeing a record is needed to change it
    for (const permission of list) {
        const [module, action] = permission.split(".");
        if (action && action !== "read" && GRANTABLE.has(`${module}.read`) && !list.includes(`${module}.read`)) list.push(`${module}.read`);
    }
    return list;
};

const checkName = async (organizationId, name, selfId = null) => {
    const clean = String(name || "").trim();
    if (clean.length < 2) throw new ApiError("Give the role a name.", 400);
    if (BUILT_IN.some(item => item.name.toLowerCase() === clean.toLowerCase())) {
        throw new ApiError(`"${clean}" is a built-in role. Choose another name.`, 409);
    }
    const taken = await Role.findOne({ organization: organizationId, isDeleted: false, ...(selfId ? { _id: { $ne: selfId } } : {}) })
        .collation({ locale: "en", strength: 2 }).where("name").equals(clean).lean();
    if (taken) throw new ApiError(`A role named "${clean}" already exists.`, 409);
    return clean;
};

const listRoles = async (organizationId) => {

    const replace = await require("./terminologyService").replacerFor(organizationId);

    const custom = await Role.find({ organization: organizationId, isDeleted: false }).sort({ name: 1 }).lean();
    const counts = await User.aggregate([
        { $match: { organization: new mongoose.Types.ObjectId(String(organizationId)) } },
        { $group: { _id: { role: "$role", customRole: "$customRole" }, n: { $sum: 1 } } }
    ]);
    const usersOf = (match) => counts.filter(match).reduce((sum, row) => sum + row.n, 0);

    return {
        builtIn: BUILT_IN.map(role => ({
            ...role,
            name: replace(role.name),
            builtIn: true,
            permissions: rolePermissions[role.key] || [],
            users: usersOf(row => row._id.role === role.key && !row._id.customRole)
        })),
        custom: custom.map(role => ({
            _id: role._id,
            name: role.name,
            description: role.description,
            permissions: role.permissions,
            builtIn: false,
            users: usersOf(row => String(row._id.customRole || "") === String(role._id))
        })),
        catalog: catalog()
    };

};

const createRole = async (organizationId, data, userId) => {
    const name = await checkName(organizationId, data.name);
    return Role.create({
        organization: organizationId, name, description: String(data.description || "").trim(),
        permissions: cleanPermissions(data.permissions), createdBy: userId
    });
};

const updateRole = async (organizationId, id, data, userId) => {
    if (!mongoose.isValidObjectId(id)) throw new ApiError("Invalid role.", 400);
    const role = await Role.findOne({ _id: id, organization: organizationId, isDeleted: false });
    if (!role) throw new ApiError("Role not found.", 404);
    if (data.name !== undefined) role.name = await checkName(organizationId, data.name, role._id);
    if (data.description !== undefined) role.description = String(data.description || "").trim();
    if (data.permissions !== undefined) role.permissions = cleanPermissions(data.permissions);
    role.updatedBy = userId;
    await role.save();
    return role;
};

const deleteRole = async (organizationId, id, userId) => {
    if (!mongoose.isValidObjectId(id)) throw new ApiError("Invalid role.", 400);
    const role = await Role.findOne({ _id: id, organization: organizationId, isDeleted: false });
    if (!role) throw new ApiError("Role not found.", 404);
    const users = await User.countDocuments({ organization: organizationId, customRole: role._id });
    if (users) throw new ApiError(`${users} user${users === 1 ? " has" : "s have"} this role. Give them another role first.`, 409);
    role.isDeleted = true;
    role.deletedAt = new Date();
    role.updatedBy = userId;
    await role.save();
    return role;
};

// the custom role given to a user (checked), or null
const resolveCustomRole = async (organizationId, customRole) => {
    if (customRole === undefined) return undefined;
    if (customRole === null || customRole === "") return null;
    if (!mongoose.isValidObjectId(customRole)) throw new ApiError("Invalid role.", 400);
    const role = await Role.findOne({ _id: customRole, organization: organizationId, isDeleted: false }).select("_id name").lean();
    if (!role) throw new ApiError("Role not found.", 404);
    return role;
};

// users whose permissions include one (e.g. budget approvers)
const usersWithPermission = async (organizationId, permission) => {
    const builtIn = Object.entries(rolePermissions)
        .filter(([role, permissions]) => role !== "super_admin" && (permissions.includes(permission) || permissions.includes("*")))
        .map(([role]) => role);
    const custom = await Role.find({ organization: organizationId, isDeleted: false, permissions: permission }).select("_id").lean();
    return User.find({
        organization: organizationId,
        status: "active",
        $or: [
            { role: { $in: builtIn }, customRole: null },
            { customRole: { $in: custom.map(role => role._id) } }
        ]
    })
        .select("name firstName lastName email role customRole")
        .lean();
};


module.exports = {
    BUILT_IN,
    permissionsOf,
    roleNameOf,
    catalog,
    listRoles,
    createRole,
    updateRole,
    deleteRole,
    resolveCustomRole,
    usersWithPermission
};
