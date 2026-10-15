const { Parser } = require("json2csv");

const {
    normalizeText
} = require("./helpers");


/* =========================================================
   CSV VALUE NORMALIZATION
========================================================= */

const normalizeCsvValue = (
    value
) => {
    if (
        value === null ||
        value === undefined
    ) {
        return "";
    }

    if (
        typeof value === "string" ||
        typeof value === "number" ||
        typeof value === "boolean"
    ) {
        return value;
    }

    if (value instanceof Date) {
        return value.toISOString();
    }

    if (Array.isArray(value)) {
        return value
            .map(
                item =>
                    normalizeCsvValue(
                        item
                    )
            )
            .join(", ");
    }

    if (
        typeof value === "object"
    ) {
        return normalizeText(
            value,
            ""
        );
    }

    return String(value);
};


/* =========================================================
   ROW NORMALIZATION
========================================================= */

const normalizeCsvRow = (
    row,
    fields
) => {
    const normalized = {};

    fields.forEach(
        field => {
            const key =
                typeof field === "string"
                    ? field
                    : field.value;

            let value;

            if (
                typeof field ===
                "string"
            ) {
                value =
                    row?.[field];
            } else if (
                typeof field.value ===
                "function"
            ) {
                value =
                    field.value(
                        row
                    );
            } else {
                value =
                    row?.[field.value];
            }

            normalized[key] =
                normalizeCsvValue(
                    value
                );
        }
    );

    return normalized;
};


/* =========================================================
   CREATE CSV
========================================================= */

const createCsv = (
    rows = [],
    options = {}
) => {
    const fields =
        options.fields ||
        [];

    const normalizedRows =
        rows.map(
            row =>
                normalizeCsvRow(
                    row,
                    fields
                )
        );

    const parser =
        new Parser({
            fields:
                fields.map(
                    field => {
                        if (
                            typeof field ===
                            "string"
                        ) {
                            return {
                                label: field,
                                value: field
                            };
                        }

                        return {
                            label:
                                field.label ||
                                field.value,

                            value:
                                field.value
                        };
                    }
                ),

            excelStrings:
                options.excelStrings ??
                false,

            withBOM:
                options.withBOM ??
                true
        });

    return parser.parse(
        normalizedRows
    );
};


/* =========================================================
   CSV FROM OBJECT ROWS
========================================================= */

const createCsvFromObjects = (
    rows = [],
    options = {}
) => {
    if (
        !rows.length
    ) {
        return "";
    }

    const firstRow =
        rows[0] || {};

    const fields =
        options.fields ||
        Object.keys(
            firstRow
        );

    return createCsv(
        rows,
        {
            ...options,
            fields
        }
    );
};


/* =========================================================
   CSV SECTIONS
========================================================= */

const createCsvSection = (
    title,
    rows = [],
    fields = []
) => {
    const sectionTitle =
        normalizeText(
            title,
            ""
        );

    const csv =
        createCsv(
            rows,
            {
                fields,
                withBOM: false
            }
        );

    if (!sectionTitle) {
        return csv;
    }

    return [
        sectionTitle,
        csv
    ]
        .filter(Boolean)
        .join("\n");
};


/* =========================================================
   EXPORT
========================================================= */

module.exports = {
    normalizeCsvValue,
    normalizeCsvRow,

    createCsv,
    createCsvFromObjects,
    createCsvSection
};