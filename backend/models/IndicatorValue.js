const mongoose = require("mongoose");

// =====================================================
// ACTUAL VALUE OF A MANUAL INDICATOR FOR ONE PERIOD
// =====================================================
//
// e.g. "% of households with improved income" for
// 2026-Q2: 64 (from the follow-up survey). Female / male
// are optional (when the indicator counts people).
//
// =====================================================

const indicatorValueSchema = new mongoose.Schema(
    {
        organization: { type: mongoose.Schema.Types.ObjectId, ref: "Organization", required: true },
        indicator: { type: mongoose.Schema.Types.ObjectId, ref: "Indicator", required: true },
        period: { type: String, required: true, trim: true },
        value: { type: Number, required: true, min: 0 },
        female: { type: Number, default: null, min: 0 },
        male: { type: Number, default: null, min: 0 },
        notes: { type: String, trim: true, default: "" },
        enteredBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null }
    },
    { timestamps: true }
);

indicatorValueSchema.index({ indicator: 1, period: 1 }, { unique: true });

module.exports = mongoose.models.IndicatorValue || mongoose.model("IndicatorValue", indicatorValueSchema);
