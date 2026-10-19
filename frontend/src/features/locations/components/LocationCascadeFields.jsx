import {
    useEffect,
    useState
} from "react";


import {
    Grid
} from "@mui/material";


import {
    AppAutoComplete,
    AppTextField
} from "../../../components/ui";


import {
    getLocationsApi
} from "../api/locationApi";


import useZoneLabel
    from "../hooks/useZoneLabel";



// =====================================================
// LOCATION CASCADE FIELDS
// =====================================================
//
// Region -> Zone -> Woreda searchable dropdowns.
//
// value:
//
// {
//     region, regionCode,
//     zone, zoneCode,
//     woreda, woredaCode
// }
//
// onChange(patch) receives only the keys that changed.
// Selecting a level clears every level below it.
//
// Older records that only have names (no codes) are
// matched by name once the options load.
//
// A region can rename its second level through
// childLabel (Addis Ababa: "Sub City"). When the
// last level has no official list (Addis woredas)
// it falls back to a free-text field.
//
// Inside FormGrid each level gets its own cell
// (FormGrid passes gridSize). renderItem(field, key)
// can wrap fields for other layouts.
//
// =====================================================

const LEVELS = [

    {
        level: 1,
        label: "Region",
        nameKey: "region",
        codeKey: "regionCode",
        parentCodeKey: null
    },

    {
        level: 2,
        label: "Zone",
        nameKey: "zone",
        codeKey: "zoneCode",
        parentCodeKey: "regionCode"
    },

    {
        level: 3,
        label: "Woreda",
        nameKey: "woreda",
        codeKey: "woredaCode",
        parentCodeKey: "zoneCode"
    }

];


// "Bole Sub City" and "Bole" are the same sub-city.

const normalizeName = (value) =>
    String(value || "")
        .trim()
        .toLowerCase()
        .replace(/s+subs*-?s*city$/, "");


const getChildPatch = (index) =>

    LEVELS

        .slice(index + 1)

        .reduce(
            (patch, config) => ({
                ...patch,
                [config.nameKey]: "",
                [config.codeKey]: ""
            }),
            {}
        );



// =====================================================
// SINGLE LEVEL
// =====================================================

const LocationLevelField = ({
    config,
    label,
    parentLabel,
    index,
    value,
    onChange,
    disabled,
    required,
    size
}) => {

    const parentCode =
        config.parentCodeKey
            ? value[config.parentCodeKey] || ""
            : "";

    const needsParent =
        Boolean(config.parentCodeKey);

    const canLoad =
        !needsParent || Boolean(parentCode);


    // -------------------------------------------------
    // LOAD OPTIONS WHEN PARENT CHANGES
    // -------------------------------------------------
    //
    // The result is stored with the parent it was
    // loaded for, so stale results are ignored and
    // loading is derived instead of set in the effect.
    //
    // -------------------------------------------------

    const [result, setResult] =
        useState({
            parentCode: null,
            options: [],
            error: ""
        });

    useEffect(() => {

        if (!canLoad) {
            return undefined;
        }

        let cancelled = false;

        getLocationsApi(
            config.level,
            parentCode
        )

            .then(items => {
                if (!cancelled) {
                    setResult({
                        parentCode,
                        options: items,
                        error: ""
                    });
                }
            })

            .catch(() => {
                if (!cancelled) {
                    setResult({
                        parentCode,
                        options: [],
                        error:
                            `Could not load ${config.label.toLowerCase()} list.`
                    });
                }
            });

        return () => {
            cancelled = true;
        };

    }, [
        config.level,
        config.label,
        canLoad,
        parentCode
    ]);


    const isCurrent =
        canLoad &&
        result.parentCode === parentCode;

    const loading =
        canLoad && !isCurrent;

    const options =
        isCurrent
            ? result.options
            : [];

    const loadError =
        isCurrent
            ? result.error
            : "";


    const currentCode =
        value[config.codeKey] || "";

    const currentName =
        value[config.nameKey] || "";


    // -------------------------------------------------
    // MATCH LEGACY NAME-ONLY VALUES
    // -------------------------------------------------

    const legacyMatch =
        !currentCode && currentName
            ? options.find(
                option =>
                    normalizeName(option.name) ===
                    normalizeName(currentName)
            )
            : null;

    useEffect(() => {

        if (legacyMatch) {

            onChange({
                [config.nameKey]:
                    legacyMatch.name,
                [config.codeKey]:
                    legacyMatch.pcode
            });

        }

    }, [
        legacyMatch,
        config.nameKey,
        config.codeKey,
        onChange
    ]);


    const selected =
        options.find(
            option =>
                option.pcode === currentCode
        ) || null;


    const unmatchedLegacy =
        !loading &&
        !selected &&
        !legacyMatch &&
        currentName &&
        canLoad;


    const handleChange = (option) => {

        onChange({
            [config.nameKey]:
                option?.name || "",
            [config.codeKey]:
                option?.pcode || "",
            ...getChildPatch(index)
        });

    };


    let helperText = loadError;

    if (!helperText && unmatchedLegacy) {
        helperText =
            `Previously entered "${currentName}" is not in the official list. Please select.`;
    }

    if (!helperText && needsParent && !parentCode) {
        helperText =
            `Select ${parentLabel.toLowerCase()} first`;
    }


    // -------------------------------------------------
    // NO OFFICIAL LIST: FREE TEXT
    // -------------------------------------------------

    const isLastLevel =
        index === LEVELS.length - 1;

    if (
        isLastLevel &&
        isCurrent &&
        !loadError &&
        options.length === 0
    ) {

        return (

            <AppTextField
                label={label}
                required={required}
                disabled={disabled}
                size={size}
                value={currentName}
                onChange={(e) =>
                    onChange({
                        [config.nameKey]:
                            e.target.value,
                        [config.codeKey]:
                            ""
                    })
                }
            />

        );

    }


    return (

        <AppAutoComplete
            label={label}
            required={required}
            value={selected}
            options={options}
            loading={loading}
            disabled={
                disabled ||
                (needsParent && !parentCode)
            }
            placeholder={`Select ${label}`}
            size={size}
            getOptionLabel={
                option =>
                    option?.name || ""
            }
            isOptionEqualToValue={
                (option, current) =>
                    option.pcode === current.pcode
            }
            onChange={handleChange}
            error={Boolean(loadError || unmatchedLegacy)}
            helperText={helperText}
        />

    );

};



// =====================================================
// CASCADE
// =====================================================

const LocationCascadeFields = ({
    value = {},
    onChange,
    disabled = false,
    required = false,
    size = "small",
    gridSize,
    renderItem
}) => {

    const wrapField =
        renderItem ||
        (
            gridSize
                ? (field, key) => (
                    <Grid
                        key={key}
                        size={gridSize}
                        sx={{
                            minWidth: 0,
                            "& > *": {
                                width: "100%",
                                minWidth: 0
                            }
                        }}
                    >
                        {field}
                    </Grid>
                )
                : (field) => field
        );


    const zoneLabel =
        useZoneLabel(
            value.regionCode
        );

    const labels =
        LEVELS.map(
            (config, index) =>
                index === 1
                    ? zoneLabel
                    : config.label
        );


    return (

        <>
            {LEVELS.map(
                (config, index) => wrapField(

                    <LocationLevelField
                        key={config.level}
                        config={config}
                        label={labels[index]}
                        parentLabel={labels[index - 1] || ""}
                        index={index}
                        value={value}
                        onChange={onChange}
                        disabled={disabled}
                        required={required}
                        size={size}
                    />,

                    config.level

                )
            )}
        </>

    );

};


// Tells FormGrid to let this component lay out its
// own cells instead of wrapping it in one.

LocationCascadeFields.formGridItems = true;


export default LocationCascadeFields;
