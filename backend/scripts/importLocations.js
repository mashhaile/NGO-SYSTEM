// =====================================================
// IMPORT ADMIN AREAS (REGION / ZONE / WOREDA)
// =====================================================
//
// Usage (from backend/):
//
//     node scripts/importLocations.js
//     node scripts/importLocations.js path/to/file.xlsx
//
// Reads the OCHA COD-AB sheets eth_admin1, eth_admin2
// and eth_admin3 and upserts them by P-code, so the
// script is safe to run again when a new version of
// the file is released.
//
// "Contested" areas (P-codes starting with ET99) are
// imported as inactive so they never show in forms.
//
// Chartered cities (see CITY_REGIONS) have a single
// placeholder zone in the source file with their
// sub-cities at level 3. Those placeholders are
// dropped and the sub-cities become level 2 directly
// under the region, labelled "Sub City".
//
// =====================================================

require("dotenv").config();

const path = require("path");
const mongoose = require("mongoose");
const XLSX = require("xlsx");

const AdminArea =
    require("../models/AdminArea");


const DEFAULT_FILE =
    path.join(
        __dirname,
        "..",
        "data",
        "locations.xlsx"
    );


const LEVELS = [

    {
        level: 1,
        sheet: "eth_admin1",
        name: "adm1_name",
        pcode: "adm1_pcode",
        parent: null
    },

    {
        level: 2,
        sheet: "eth_admin2",
        name: "adm2_name",
        pcode: "adm2_pcode",
        parent: "adm1_pcode"
    },

    {
        level: 3,
        sheet: "eth_admin3",
        name: "adm3_name",
        pcode: "adm3_pcode",
        parent: "adm2_pcode"
    }

];


// Addis Ababa: Region -> Sub City -> Woreda.
// The file has "Region 14" (ET1401) as its only zone.

const CITY_REGIONS = {

    ET14: {
        placeholderZone: "ET1401",
        childLabel: "Sub City",
        nameSuffix: / Sub City$/i
    }

};


const PLACEHOLDER_ZONES =
    Object.entries(CITY_REGIONS)
        .reduce(
            (map, [regionPcode, city]) => ({
                ...map,
                [city.placeholderZone]: {
                    ...city,
                    regionPcode
                }
            }),
            {}
        );


const toPcode = (value) =>
    value
        ? String(value)
            .trim()
            .toUpperCase()
        : null;


// =====================================================
// BUILD AREA FROM SHEET ROW
// =====================================================
//
// Returns null for rows that should not be imported.
//
// =====================================================

const buildArea = (config, row) => {

    const pcode =
        toPcode(row[config.pcode]);

    const area = {
        pcode,
        name:
            String(row[config.name]).trim(),
        level:
            config.level,
        parentPcode:
            config.parent
                ? toPcode(row[config.parent])
                : null,
        childLabel:
            null
    };


    if (config.level === 1) {

        area.childLabel =
            CITY_REGIONS[pcode]?.childLabel ||
            null;

    }


    if (
        config.level === 2 &&
        PLACEHOLDER_ZONES[pcode]
    ) {
        return null;
    }


    const city =
        config.level === 3
            ? PLACEHOLDER_ZONES[area.parentPcode]
            : null;

    if (city) {

        area.level = 2;

        area.parentPcode =
            city.regionPcode;

        area.name =
            area.name
                .replace(city.nameSuffix, "")
                .trim();

    }


    return area;

};


const isContested = (pcode) =>
    String(pcode || "")
        .toUpperCase()
        .startsWith("ET99");


const importLocations = async () => {

    const filePath =
        process.argv[2] ||
        DEFAULT_FILE;

    const workbook =
        XLSX.readFile(filePath);


    await mongoose.connect(
        process.env.MONGO_URI
    );

    console.log(
        `Importing locations from ${filePath}`
    );


    for (const config of LEVELS) {

        const sheet =
            workbook.Sheets[config.sheet];

        if (!sheet) {
            throw new Error(
                `Sheet "${config.sheet}" not found.`
            );
        }


        const rows =
            XLSX.utils.sheet_to_json(sheet);


        const operations =
            rows

                .filter(
                    row =>
                        row[config.pcode] &&
                        row[config.name]
                )

                .map(row => ({
                    row,
                    area:
                        buildArea(config, row)
                }))

                .filter(item => item.area)

                .map(({ row, area }) => {

                    const {
                        pcode,
                        ...fields
                    } = area;

                    return {
                        updateOne: {
                            filter: {
                                pcode
                            },
                            update: {
                                $set: {
                                    ...fields,
                                    active:
                                        !isContested(pcode),
                                    version:
                                        row.version || null
                                }
                            },
                            upsert: true
                        }
                    };

                });


        const result =
            await AdminArea.bulkWrite(
                operations
            );

        console.log(
            `Level ${config.level} (${config.sheet}): ` +
            `${operations.length} rows, ` +
            `${result.upsertedCount} new, ` +
            `${result.modifiedCount} updated`
        );

    }


    // Remove placeholder zones left by earlier imports.

    const removed =
        await AdminArea.deleteMany({
            pcode: {
                $in: Object.keys(PLACEHOLDER_ZONES)
            }
        });

    if (removed.deletedCount) {
        console.log(
            `Removed ${removed.deletedCount} placeholder zone(s)`
        );
    }

};


importLocations()

    .then(() => {
        console.log("✅ Locations imported");
    })

    .catch(error => {
        console.error(
            "❌ Location import failed:",
            error.message
        );
        process.exitCode = 1;
    })

    .finally(() =>
        mongoose.disconnect()
    );
