const mongoose = require("mongoose");

const Supplier = require("../models/Supplier");

const {
    SUPPLIER_STATUS,
    SUPPLIER_CATEGORIES
} = require("../models/Supplier");

const ApiError = require("../utils/apiError");

const escapeRegex = require("../utils/escapeRegex");

const generateSequence = require("../utils/generateSequence");


// =====================================================
// SUPPLIERS (procurement)
// =====================================================
//
// - A name is used once per organization (any case).
// - Blacklisting needs a reason; it stays on the record.
// - A supplier used by a purchase request is never deleted;
//   set it Inactive instead.
//
// =====================================================

const FIELDS = [
    "name", "categories", "supplies", "tin", "vatRegistered", "licenseNumber",
    "contactPerson", "phone", "email", "address",
    "bankName", "bankAccountName", "bankAccountNumber",
    "status", "statusReason", "notes"
];

const notFound = () => new ApiError("Supplier not found.", 404);

const pick = (data) =>
    Object.fromEntries(FIELDS.filter(field => data[field] !== undefined).map(field => [field, data[field]]));


const findSupplier = async (id, organizationId) => {

    if (!mongoose.isValidObjectId(id)) throw notFound();

    const supplier = await Supplier.findOne({ _id: id, organization: organizationId, isDeleted: false });

    if (!supplier) throw notFound();

    return supplier;

};


const checkName = async (organizationId, name, selfId = null) => {

    const clean = String(name || "").trim();

    if (clean.length < 2) throw new ApiError("Enter the supplier's name.", 400);

    const taken =
        await Supplier.findOne({
            organization: organizationId,
            isDeleted: false,
            name: { $regex: `^${escapeRegex(clean)}$`, $options: "i" },
            ...(selfId ? { _id: { $ne: selfId } } : {})
        })
            .select("supplierCode name")
            .lean();

    if (taken) throw new ApiError(`${taken.name} is already in the supplier list (${taken.supplierCode}).`, 409);

    return clean;

};


const checkStatus = (data) => {
    if (data.status === SUPPLIER_STATUS.BLACKLISTED && String(data.statusReason || "").trim().length < 3) {
        throw new ApiError("Give the reason the supplier is blacklisted.", 400);
    }
};


// ---------------------------------------------------------------- create / update / delete

const createSupplier = async (data, organizationId, userId) => {

    const values = pick(data);

    values.name = await checkName(organizationId, values.name);
    checkStatus(values);

    const supplier =
        await Supplier.create({
            organization: organizationId,
            supplierCode: await generateSequence("Supplier", "SUP", organizationId),
            ...values,
            createdBy: userId,
            updatedBy: userId
        });

    return getSupplierById(supplier._id, organizationId);

};


const updateSupplier = async (id, data, organizationId, userId) => {

    const supplier = await findSupplier(id, organizationId);

    const values = pick(data);

    if (values.name !== undefined) values.name = await checkName(organizationId, values.name, supplier._id);

    checkStatus({ status: values.status ?? supplier.status, statusReason: values.statusReason ?? supplier.statusReason });

    // back to Active: the old reason no longer applies
    if (values.status === SUPPLIER_STATUS.ACTIVE) values.statusReason = "";

    Object.assign(supplier, values, { updatedBy: userId });

    await supplier.save();

    return getSupplierById(supplier._id, organizationId);

};


const deleteSupplier = async (id, organizationId, userId) => {

    const supplier = await findSupplier(id, organizationId);

    const used =
        await mongoose.model("PurchaseRequest").countDocuments({ organization: organizationId, suggestedSupplier: supplier._id, isDeleted: false });

    if (used) {
        throw new ApiError(
            `${supplier.name} is used by ${used} purchase request${used === 1 ? "" : "s"} and cannot be deleted. Set it Inactive instead.`,
            409
        );
    }

    supplier.isDeleted = true;
    supplier.deletedAt = new Date();
    supplier.deletedBy = userId;

    await supplier.save();

};


// ---------------------------------------------------------------- read

const getSuppliers = async (organizationId, query = {}) => {

    const page = Math.max(1, Number(query.page) || 1);
    const limit = Math.min(200, Math.max(1, Number(query.limit) || 10));

    const filter = { organization: organizationId, isDeleted: false };

    if (query.status) filter.status = query.status;
    if (query.category && SUPPLIER_CATEGORIES.includes(query.category)) filter.categories = query.category;

    if (query.search) {
        const pattern = { $regex: escapeRegex(query.search), $options: "i" };
        filter.$or = [
            { supplierCode: pattern },
            { name: pattern },
            { supplies: pattern },
            { tin: pattern },
            { contactPerson: pattern },
            { phone: pattern }
        ];
    }

    const [data, total] =
        await Promise.all([
            Supplier.find(filter)
                .select("supplierCode name categories supplies tin vatRegistered contactPerson phone email status statusReason")
                .sort({ name: 1 })
                .skip((page - 1) * limit)
                .limit(limit)
                .lean(),
            Supplier.countDocuments(filter)
        ]);

    return {
        data,
        pagination: { total, page, limit, pages: Math.ceil(total / limit) }
    };

};


// for pickers: the active suppliers
const getSupplierOptions = async (organizationId) =>
    Supplier.find({ organization: organizationId, isDeleted: false, status: SUPPLIER_STATUS.ACTIVE })
        .select("supplierCode name categories supplies")
        .sort({ name: 1 })
        .lean();


const getSupplierById = async (id, organizationId) => {

    if (!mongoose.isValidObjectId(id)) throw notFound();

    const supplier =
        await Supplier.findOne({ _id: id, organization: organizationId, isDeleted: false })
            .populate("createdBy", "name email")
            .populate("updatedBy", "name email")
            .lean();

    if (!supplier) throw notFound();

    // the purchase requests that suggested it (newest first)
    const requests =
        await mongoose.model("PurchaseRequest")
            .find({ organization: organizationId, suggestedSupplier: supplier._id, isDeleted: false })
            .select("requestCode title requestDate status estimatedTotal currency")
            .sort({ requestDate: -1 })
            .limit(20)
            .lean();

    return { ...supplier, requests };

};


module.exports = {
    createSupplier,
    updateSupplier,
    deleteSupplier,
    getSuppliers,
    getSupplierOptions,
    getSupplierById,
    SUPPLIER_STATUS
};
