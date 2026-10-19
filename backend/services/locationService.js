const AdminArea =
    require("../models/AdminArea");


// =====================================================
// NORMALIZE LOCATION NAME
// =====================================================
//
// Case and spacing insensitive.
// "Bole Sub City" and "Bole" are the same sub-city.
//
// =====================================================

const normalizeLocationName = (value) =>
    String(value || "")
        .trim()
        .toLowerCase()
        .replace(/\s+/g, " ")
        .replace(/\s+sub\s*-?\s*city$/, "");


// =====================================================
// CREATE LOCATION RESOLVER
// =====================================================
//
// Loads all active admin areas once, then resolves
// region / zone / woreda names (or P-codes) to the
// official names and codes.
//
// Use one resolver per batch (e.g. an Excel import).
//
// resolve({ region, zone, woreda }) returns:
//
// {
//     region, regionCode,
//     zone, zoneCode,
//     woreda, woredaCode
// }
//
// and throws a readable Error when a value is not in
// the official list or a parent level is missing.
//
// A woreda under an area with no official woredas
// (Addis Ababa sub-cities) is kept as free text.
//
// =====================================================

const createLocationResolver =
    async () => {

        const areas =
            await AdminArea

                .find({
                    active: true
                })

                .select(
                    "pcode name level parentPcode childLabel"
                )

                .lean();


        const byPcode =
            new Map();

        const childrenByParent =
            new Map();

        areas.forEach(area => {

            byPcode.set(
                area.pcode,
                area
            );

            const parentKey =
                area.parentPcode || "";

            if (!childrenByParent.has(parentKey)) {
                childrenByParent.set(
                    parentKey,
                    []
                );
            }

            childrenByParent
                .get(parentKey)
                .push(area);

        });


        const findChild = (
            parentPcode,
            level,
            input
        ) => {

            const code =
                String(input)
                    .trim()
                    .toUpperCase();

            const name =
                normalizeLocationName(input);

            return (
                childrenByParent.get(parentPcode || "") ||
                []
            ).find(
                area =>
                    area.level === level &&
                    (
                        area.pcode === code ||
                        normalizeLocationName(area.name) === name
                    )
            );

        };


        const resolve = ({
            region = "",
            zone = "",
            woreda = ""
        } = {}) => {

            const resolved = {
                region: "",
                regionCode: "",
                zone: "",
                zoneCode: "",
                woreda: "",
                woredaCode: ""
            };


            // ---------------------------------------------
            // REGION
            // ---------------------------------------------

            if (!region) {

                if (zone || woreda) {
                    throw new Error(
                        "Region is required when Zone or Woreda is provided"
                    );
                }

                return resolved;

            }

            const regionArea =
                findChild(null, 1, region);

            if (!regionArea) {
                throw new Error(
                    `Region "${region}" not found in the official location list`
                );
            }

            resolved.region =
                regionArea.name;

            resolved.regionCode =
                regionArea.pcode;


            // ---------------------------------------------
            // ZONE / SUB CITY
            // ---------------------------------------------

            const zoneLabel =
                regionArea.childLabel ||
                "Zone";

            if (!zone) {

                if (woreda) {
                    throw new Error(
                        `${zoneLabel} is required when Woreda is provided`
                    );
                }

                return resolved;

            }

            const zoneArea =
                findChild(
                    regionArea.pcode,
                    2,
                    zone
                );

            if (!zoneArea) {
                throw new Error(
                    `${zoneLabel} "${zone}" not found in region "${regionArea.name}"`
                );
            }

            resolved.zone =
                zoneArea.name;

            resolved.zoneCode =
                zoneArea.pcode;


            // ---------------------------------------------
            // WOREDA
            // ---------------------------------------------

            if (!woreda) {
                return resolved;
            }

            const hasOfficialWoredas =
                (childrenByParent.get(zoneArea.pcode) || [])
                    .length > 0;

            if (!hasOfficialWoredas) {

                resolved.woreda =
                    String(woreda).trim();

                return resolved;

            }

            const woredaArea =
                findChild(
                    zoneArea.pcode,
                    3,
                    woreda
                );

            if (!woredaArea) {
                throw new Error(
                    `Woreda "${woreda}" not found in ${zoneLabel.toLowerCase()} "${zoneArea.name}"`
                );
            }

            resolved.woreda =
                woredaArea.name;

            resolved.woredaCode =
                woredaArea.pcode;

            return resolved;

        };


        // -------------------------------------------------
        // LENIENT MATCH
        // -------------------------------------------------
        //
        // Matches as many levels as possible, top down,
        // without throwing. Used to add codes to records
        // saved before the official list existed.
        //
        // -------------------------------------------------

        const matchPartial = ({
            region = "",
            zone = "",
            woreda = ""
        } = {}) => {

            const regionArea =
                region
                    ? findChild(null, 1, region)
                    : null;

            const zoneArea =
                regionArea && zone
                    ? findChild(regionArea.pcode, 2, zone)
                    : null;

            const woredaArea =
                zoneArea && woreda
                    ? findChild(zoneArea.pcode, 3, woreda)
                    : null;

            return {
                regionArea: regionArea || null,
                zoneArea: zoneArea || null,
                woredaArea: woredaArea || null
            };

        };


        return {
            resolve,
            matchPartial
        };

    };


module.exports = {
    normalizeLocationName,
    createLocationResolver
};
