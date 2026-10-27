const mongoose = require("mongoose");

// =====================================================
// M&E INDICATOR (module "me")
// =====================================================
//
// One indicator of a program's (or project's) logframe:
// the result it measures (Goal / Outcome / Output), its
// baseline, its targets per period, and where its actual
// values come from:
//
//   source "auto"   computed from the system's records for
//                   the period (measure: see
//                   services/indicatorMeasures.js)
//   source "manual" entered per period (IndicatorValue)
//
// Periods follow the frequency: "2026" (Annual),
// "2026-Q1" (Quarterly), "2026-01" (Monthly).
//
// =====================================================

const LEVELS = ["Goal", "Outcome", "Output"];
const UNITS = ["number", "percent"];
const DIRECTIONS = ["increase", "decrease"];
const FREQUENCIES = ["Annual", "Quarterly", "Monthly"];
const SOURCES = ["auto", "manual"];

const targetSchema = new mongoose.Schema(
    {
        period: { type: String, required: true, trim: true },
        value: { type: Number, required: true, min: 0 }
    },
    { _id: false }
);

const indicatorSchema = new mongoose.Schema(
    {
        organization: { type: mongoose.Schema.Types.ObjectId, ref: "Organization", required: true, index: true },

        program: { type: mongoose.Schema.Types.ObjectId, ref: "Program", required: true },
        // empty: an indicator of the whole program
        project: { type: mongoose.Schema.Types.ObjectId, ref: "Project", default: null },

        code: { type: String, trim: true },

        // the logframe result it measures
        level: { type: String, enum: LEVELS, required: true, default: "Output" },
        result: { type: String, trim: true, default: "" },

        name: { type: String, required: true, trim: true },
        definition: { type: String, trim: true, default: "" },

        unit: { type: String, enum: UNITS, default: "number" },
        direction: { type: String, enum: DIRECTIONS, default: "increase" },

        baseline: {
            value: { type: Number, default: null },
            date: { type: Date, default: null }
        },

        frequency: { type: String, enum: FREQUENCIES, default: "Annual" },
        targets: { type: [targetSchema], default: [] },

        source: { type: String, enum: SOURCES, default: "manual" },
        // for source "auto": what is counted (services/indicatorMeasures.js)
        measure: { type: String, default: null },

        // means of verification and who reports it
        dataSource: { type: String, trim: true, default: "" },
        responsible: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },

        status: { type: String, enum: ["Active", "Inactive"], default: "Active" },

        createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
        updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
        isDeleted: { type: Boolean, default: false },
        deletedAt: { type: Date, default: null }
    },
    { timestamps: true }
);

indicatorSchema.index({ organization: 1, program: 1, project: 1, isDeleted: 1 });
indicatorSchema.index(
    { organization: 1, code: 1 },
    { unique: true, partialFilterExpression: { code: { $type: "string" } } }
);

module.exports = mongoose.models.Indicator || mongoose.model("Indicator", indicatorSchema);
module.exports.LEVELS = LEVELS;
module.exports.UNITS = UNITS;
module.exports.DIRECTIONS = DIRECTIONS;
module.exports.FREQUENCIES = FREQUENCIES;
module.exports.SOURCES = SOURCES;
