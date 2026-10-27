const mongoose = require("mongoose");


// =====================================================
// SUPPLIER (procurement)
// =====================================================
//
// The organization's register of suppliers: who it buys
// goods, services, works or consultancy from. Purchase
// requests may suggest one; quotations and purchase orders
// (later) are made with them.
//
//   Active       can be used
//   Inactive     kept for history, not offered for new work
//   Blacklisted  must not be used (with the reason)
//
// =====================================================

const SUPPLIER_STATUS = {
    ACTIVE: "Active",
    INACTIVE: "Inactive",
    BLACKLISTED: "Blacklisted"
};

const SUPPLIER_CATEGORIES = [
    "Goods",
    "Services",
    "Works",
    "Consultancy"
];


const SupplierSchema =
    new mongoose.Schema(
        {
            organization: {
                type: mongoose.Schema.Types.ObjectId,
                ref: "Organization",
                required: true,
                index: true
            },

            supplierCode: { type: String, trim: true },

            name: { type: String, trim: true, required: true },
            categories: { type: [{ type: String, enum: SUPPLIER_CATEGORIES }], default: [] },
            // what they supply, in words ("stationery, printing")
            supplies: { type: String, trim: true, default: "" },

            tin: { type: String, trim: true, default: "" },
            vatRegistered: { type: Boolean, default: false },
            licenseNumber: { type: String, trim: true, default: "" },

            contactPerson: { type: String, trim: true, default: "" },
            phone: { type: String, trim: true, default: "" },
            email: { type: String, trim: true, lowercase: true, default: "" },
            address: { type: String, trim: true, default: "" },

            bankName: { type: String, trim: true, default: "" },
            bankAccountName: { type: String, trim: true, default: "" },
            bankAccountNumber: { type: String, trim: true, default: "" },

            status: {
                type: String,
                enum: Object.values(SUPPLIER_STATUS),
                default: SUPPLIER_STATUS.ACTIVE
            },
            statusReason: { type: String, trim: true, default: "" },

            notes: { type: String, trim: true, default: "" },

            createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
            updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },

            isDeleted: { type: Boolean, default: false },
            deletedAt: { type: Date, default: null },
            deletedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null }
        },
        {
            timestamps: true
        }
    );


SupplierSchema.index({ organization: 1, isDeleted: 1, name: 1 });


module.exports =
    mongoose.models.Supplier ||
    mongoose.model("Supplier", SupplierSchema);

module.exports.SUPPLIER_STATUS = SUPPLIER_STATUS;
module.exports.SUPPLIER_CATEGORIES = SUPPLIER_CATEGORIES;
