const mongoose = require("mongoose");


// =====================================================
// GOODS RECEIVED NOTE (procurement)
// =====================================================
//
// What arrived against a purchase order on one day: per
// order item, the quantity accepted and the quantity
// rejected (returned to the supplier), with a remark. An
// order can have several (partial deliveries); together they
// never accept more than was ordered.
//
//   Recorded -> Cancelled (reason)   while the order has no
//                                    payments
//
// Only accepted quantities count as received and can be
// paid for.
//
// =====================================================

const GOODS_RECEIPT_STATUS = {
    RECORDED: "Recorded",
    CANCELLED: "Cancelled"
};


const lineSchema =
    new mongoose.Schema(
        {
            // the purchase order item
            item: { type: mongoose.Schema.Types.ObjectId, required: true },
            description: { type: String, trim: true, default: "" },
            unit: { type: String, trim: true, default: "" },
            accepted: { type: Number, min: 0, default: 0 },
            rejected: { type: Number, min: 0, default: 0 },
            remark: { type: String, trim: true, default: "" }
        },
        { _id: false }
    );


const GoodsReceiptSchema =
    new mongoose.Schema(
        {
            organization: {
                type: mongoose.Schema.Types.ObjectId,
                ref: "Organization",
                required: true,
                index: true
            },

            grnCode: { type: String, trim: true },

            purchaseOrder: { type: mongoose.Schema.Types.ObjectId, ref: "PurchaseOrder", required: true, index: true },
            supplier: { type: mongoose.Schema.Types.ObjectId, ref: "Supplier", required: true },

            receivedDate: { type: Date, required: true },
            // the supplier's delivery note / waybill number
            deliveryNote: { type: String, trim: true, default: "" },
            receivedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
            notes: { type: String, trim: true, default: "" },

            lines: { type: [lineSchema], default: [] },

            // value of what was accepted, at the order's prices (order currency)
            value: { type: Number, min: 0, default: 0 },

            status: {
                type: String,
                enum: Object.values(GOODS_RECEIPT_STATUS),
                default: GOODS_RECEIPT_STATUS.RECORDED
            },

            cancelledBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
            cancelledAt: { type: Date, default: null },
            cancelReason: { type: String, default: "" },

            createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null }
        },
        {
            timestamps: true
        }
    );


GoodsReceiptSchema.plugin(
    require("./plugins/dateRules"),
    {
        what: "This goods received note",
        labels: { receivedDate: "received date" },
        rules: [
            { notFuture: "receivedDate", because: "Record goods on the day they arrived." }
        ]
    }
);


module.exports =
    mongoose.models.GoodsReceipt ||
    mongoose.model("GoodsReceipt", GoodsReceiptSchema);

module.exports.GOODS_RECEIPT_STATUS = GOODS_RECEIPT_STATUS;
