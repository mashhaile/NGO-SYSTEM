const mongoose = require("mongoose");


// =====================================================
// ADMIN AREA
// =====================================================
//
// System-wide administrative boundaries, shared by
// all organizations (not tenant scoped).
//
// Source: OCHA COD-AB Ethiopia (data/locations.xlsx),
// loaded by scripts/importLocations.js
//
// Levels:
//
// 1 = Region
// 2 = Zone
// 3 = Woreda
//
// Chartered cities skip the zone level:
//
// Addis Ababa (ET14) -> Sub City (level 2) -> Woreda
// (Addis woredas are not in the file, so level 3 is
// empty there and the form falls back to text.)
//
// Hierarchy is expressed with official P-codes:
//
// ET03 (Amhara) -> ET0301 (North Gondar) -> ET030101
//
// =====================================================

const adminAreaSchema =
    new mongoose.Schema(
        {

            pcode: {
                type: String,
                required: true,
                unique: true,
                trim: true,
                uppercase: true
            },

            name: {
                type: String,
                required: true,
                trim: true
            },

            level: {
                type: Number,
                required: true,
                enum: [1, 2, 3]
            },

            parentPcode: {
                type: String,
                default: null,
                trim: true,
                uppercase: true
            },

            // Label for this area's children when it is
            // not "Zone", e.g. "Sub City" for Addis Ababa.

            childLabel: {
                type: String,
                default: null
            },

            active: {
                type: Boolean,
                default: true
            },

            version: {
                type: String,
                default: null
            }

        },
        {
            timestamps: true
        }
    );


// =====================================================
// INDEXES
// =====================================================

adminAreaSchema.index({
    level: 1,
    parentPcode: 1,
    name: 1
});


module.exports =
    mongoose.model(
        "AdminArea",
        adminAreaSchema
    );
