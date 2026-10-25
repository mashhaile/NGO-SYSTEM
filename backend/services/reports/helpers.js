const mongoose = require("mongoose");

/* =========================================================
   BASIC VALUE HELPERS
========================================================= */

const isNil = (value) =>
    value === null ||
    value === undefined;

const isObjectId = (value) =>
    value instanceof mongoose.Types.ObjectId ||
    (
        typeof value === "string" &&
        mongoose.Types.ObjectId.isValid(value)
    );

const toNumber = (value, fallback = 0) => {
    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {
        return fallback;
    }

    const number = Number(value);

    return Number.isFinite(number)
        ? number
        : fallback;
};

const normalizeText = (
    value,
    fallback = ""
) => {
    if (
        value === null ||
        value === undefined
    ) {
        return fallback;
    }

    if (
        typeof value === "string"
    ) {
        return value;
    }

    if (
        typeof value === "number" ||
        typeof value === "boolean"
    ) {
        return String(value);
    }

    if (
        value instanceof Date
    ) {
        return value.toISOString();
    }

    /*
     * Mongoose ObjectId
     */
    if (
        value &&
        value.constructor &&
        value.constructor.name === "ObjectId"
    ) {
        return value.toString();
    }

    /*
     * Objects that provide a safe string representation.
     */
    if (
        typeof value.toString === "function" &&
        value.toString !== Object.prototype.toString
    ) {
        const stringValue =
            value.toString();

        if (
            stringValue &&
            stringValue !== "[object Object]"
        ) {
            return stringValue;
        }
    }

    /*
     * Plain objects.
     */
    if (
        typeof value === "object"
    ) {
        const name =
            value.name ??
            value.label ??
            value.value ??
            value.code;

        if (
            name !== undefined &&
            name !== value
        ) {
            return normalizeText(
                name,
                fallback
            );
        }

        return fallback;
    }

    return String(value);
};


/* =========================================================
   NAME HELPERS
========================================================= */

const getName = (value, fallback = "—") => {
    if (isNil(value)) {
        return fallback;
    }

    if (typeof value === "string") {
        return value.trim() || fallback;
    }

    if (typeof value === "number") {
        return String(value);
    }

    if (typeof value !== "object") {
        return fallback;
    }

    if (value.fullName) {
        return normalizeText(value.fullName, fallback);
    }

    if (value.name) {
        return normalizeText(value.name, fallback);
    }

    if (value.displayName) {
        return normalizeText(value.displayName, fallback);
    }

    const firstName =
        normalizeText(value.firstName, "");

    const middleName =
        normalizeText(value.middleName, "");

    const lastName =
        normalizeText(value.lastName, "");

    const parts = [
        firstName,
        middleName,
        lastName
    ].filter(Boolean);

    if (parts.length) {
        return parts.join(" ");
    }

    return normalizeText(value, fallback);
};

const getCode = (value, fallback = "—") => {
    if (isNil(value)) {
        return fallback;
    }

    if (typeof value === "object") {
        return normalizeText(
            value.code ??
            value.value ??
            value.name ??
            value._id ??
            value.id,
            fallback
        );
    }

    return normalizeText(value, fallback);
};


/* =========================================================
   ID HELPERS
========================================================= */

const getId = (value) => {
    if (isNil(value)) {
        return null;
    }

    if (typeof value === "object") {
        return (
            value._id ??
            value.id ??
            null
        );
    }

    return value;
};

const sameId = (a, b) => {
    const first = getId(a);
    const second = getId(b);

    if (
        isNil(first) ||
        isNil(second)
    ) {
        return false;
    }

    return String(first) === String(second);
};


/* =========================================================
   UNIT HELPERS
========================================================= */

const getUnitObject = (unit) => {
    if (!unit) {
        return null;
    }

    if (typeof unit === "object") {
        return {
            id:
                unit._id ??
                unit.id ??
                null,

            name:
                unit.name ??
                null,

            value:
                unit.value ??
                null,

            code:
                unit.code ??
                null
        };
    }

    return {
        id: unit,
        name: null,
        value: null,
        code: null
    };
};

const getUnitName = (unit, fallback = "—") => {
    const normalized =
        getUnitObject(unit);

    if (!normalized) {
        return fallback;
    }

    return normalizeText(
        normalized.name ??
        normalized.value ??
        normalized.code ??
        normalized.id,
        fallback
    );
};

const getUnitId = (unit) => {
    const normalized =
        getUnitObject(unit);

    return normalized?.id
        ? String(normalized.id)
        : null;
};

const unitsMatch = (first, second) => {
    const firstId = getUnitId(first);
    const secondId = getUnitId(second);

    if (
        firstId &&
        secondId
    ) {
        return firstId === secondId;
    }

    const firstName =
        getUnitName(first, "")
            .toLowerCase();

    const secondName =
        getUnitName(second, "")
            .toLowerCase();

    return (
        firstName &&
        secondName &&
        firstName === secondName
    );
};


/* =========================================================
   MONEY / DATE HELPERS
========================================================= */

const formatMoney = (
    value,
    currency = "ETB"
) => {
    const amount =
        toNumber(value, 0);

    return `${currency} ${amount.toLocaleString(
        "en-US",
        {
            minimumFractionDigits: 2,
            maximumFractionDigits: 2
        }
    )}`;
};

const formatNumber = (
    value,
    decimals = 2
) => {
    const number =
        toNumber(value, 0);

    return number.toLocaleString(
        "en-US",
        {
            minimumFractionDigits: decimals,
            maximumFractionDigits: decimals
        }
    );
};

// DD/MM/YYYY (and HH:mm), like every other date in the system
const formatDate = (
    value,
    fallback = "—"
) =>
    require("../../utils/dateFormat").formatDate(value, fallback);

const formatDateTime = (
    value,
    fallback = "—"
) =>
    require("../../utils/dateFormat").formatDateTime(value, fallback);


/* =========================================================
   ALLOCATION HELPERS
========================================================= */

const normalizeAllocationBehavior = (
    value
) => {
    const text =
        normalizeText(
            value,
            ""
        )
            .trim()
            .toLowerCase();

    if (!text) {
        return "—";
    }

    if (
        text.includes("participation")
    ) {
        return "Participation";
    }

    if (
        text.includes("monetary") ||
        text.includes("financial")
    ) {
        return "Monetary";
    }

    if (
        text.includes("consumption")
    ) {
        return "Consumption";
    }

    return normalizeText(
        value,
        "—"
    );
};

const isMonetaryUnit = (unit) => {
    const text =
        getUnitName(unit, "")
            .toLowerCase();

    return (
        text.includes("amount") ||
        text.includes("financial") ||
        text.includes("cash") ||
        text.includes("currency") ||
        text.includes("etb") ||
        text.includes("birr") ||
        text.includes("money") ||
        text.includes("monetary")
    );
};


/* =========================================================
   ARRAY / OBJECT HELPERS
========================================================= */

const asArray = (value) => {
    if (Array.isArray(value)) {
        return value;
    }

    return [];
};

const firstDefined = (
    ...values
) => {
    for (const value of values) {
        if (!isNil(value)) {
            return value;
        }
    }

    return null;
};


/* =========================================================
   EXPORTS
========================================================= */

// =====================================================
// DELIVERY LOCATION
// =====================================================
//
// "Venue, Woreda, Zone, Region" from a delivery (or
// any record with those fields). Falls back to legacy
// location text.
//
// =====================================================

const formatDeliveryLocation = (record) => {

    if (!record || typeof record !== "object") {
        return "";
    }

    const site =
        record.deliveryLocation ||
        record.location ||
        record.site ||
        "";

    return [
        site,
        record.woreda,
        record.zone,
        record.region
    ]
        .map(part =>
            typeof part === "string"
                ? part.trim()
                : ""
        )
        .filter(Boolean)
        .filter(
            (part, index, parts) =>
                parts.indexOf(part) === index
        )
        .join(", ");

};


module.exports = {
    formatDeliveryLocation,

    isNil,
    isObjectId,

    toNumber,
    normalizeText,

    getName,
    getCode,

    getId,
    sameId,

    getUnitObject,
    getUnitName,
    getUnitId,
    unitsMatch,

    formatMoney,
    formatNumber,
    formatDate,
    formatDateTime,

    normalizeAllocationBehavior,
    isMonetaryUnit,

    asArray,
    firstDefined
};