// =====================================================
// SERVICE DELIVERY UNIT DEFINITIONS
// =====================================================
//
// These are PLATFORM DEFAULT UNIT DEFINITIONS.
//
// IMPORTANT:
//
// The database Lookup collection is the runtime source
// of truth for organization Unit records.
//
// This configuration defines the standard units that
// should be seeded for every organization.
//
// Unit semantics:
//
//     monetary
//         Allocation is based on allocatedValue.
//
//     physical
//         Allocation is based on quantity.
//         allocatedValue is optional.
//
// Organizations may add their own units through
// Lookup Management.
//
// =====================================================


// =====================================================
// STANDARD SERVICE DELIVERY UNITS
// =====================================================

// legacy: true = duplicate of another unit (Amount / Birr /
// Money / Cash = ETB, Pieces = Piece, Kilogram = Kg, Litre =
// Liter). Still recognized for old records, but not seeded
// for organizations (scripts/cleanupDefaultLookups.js hides
// them in existing ones).

const SERVICE_DELIVERY_UNIT_DEFINITIONS = [

    // =================================================
    // MONETARY UNITS
    // =================================================

    {
        code:
            "AMOUNT",

        value:
            "Amount",

        semanticType:
            "monetary",

        isSystemDefault:
            true,

        // Duplicate of a kept unit: still recognized, not seeded
        legacy:
            true
    },

    {
        code:
            "ETB",

        value:
            "ETB",

        semanticType:
            "monetary",

        isSystemDefault:
            true
    },

    {
        code:
            "BIRR",

        value:
            "Birr",

        semanticType:
            "monetary",

        isSystemDefault:
            true,

        // Duplicate of a kept unit: still recognized, not seeded
        legacy:
            true
    },

    {
        code:
            "MONEY",

        value:
            "Money",

        semanticType:
            "monetary",

        isSystemDefault:
            true,

        // Duplicate of a kept unit: still recognized, not seeded
        legacy:
            true
    },

    {
        code:
            "CASH",

        value:
            "Cash",

        semanticType:
            "monetary",

        isSystemDefault:
            true,

        // Duplicate of a kept unit: still recognized, not seeded
        legacy:
            true
    },


    // =================================================
    // PHYSICAL UNITS
    // =================================================

    {
        code:
            "PIECE",

        value:
            "Piece",

        semanticType:
            "physical",

        isSystemDefault:
            true
    },

    {
        code:
            "PCS",

        value:
            "Pieces",

        semanticType:
            "physical",

        isSystemDefault:
            true,

        // Duplicate of a kept unit: still recognized, not seeded
        legacy:
            true
    },

    {
        code:
            "BOX",

        value:
            "Box",

        semanticType:
            "physical",

        isSystemDefault:
            true
    },

    {
        code:
            "KG",

        value:
            "Kg",

        semanticType:
            "physical",

        isSystemDefault:
            true
    },

    {
        code:
            "KILOGRAM",

        value:
            "Kilogram",

        semanticType:
            "physical",

        isSystemDefault:
            true,

        // Duplicate of a kept unit: still recognized, not seeded
        legacy:
            true
    },

    {
        code:
            "LITER",

        value:
            "Liter",

        semanticType:
            "physical",

        isSystemDefault:
            true
    },

    {
        code:
            "LITRE",

        value:
            "Litre",

        semanticType:
            "physical",

        isSystemDefault:
            true,

        // Duplicate of a kept unit: still recognized, not seeded
        legacy:
            true
    },

    {
        code:
            "METER",

        value:
            "Meter",

        semanticType:
            "physical",

        isSystemDefault:
            true
    },

    {
        code:
            "SESSION",

        value:
            "Session",

        semanticType:
            "physical",

        isSystemDefault:
            true
    },

    {
        code:
            "DAY",

        value:
            "Day",

        semanticType:
            "physical",

        isSystemDefault:
            true
    },

    {
        code:
            "HOUR",

        value:
            "Hour",

        semanticType:
            "physical",

        isSystemDefault:
            true
    },

    {
        code:
            "PACK",

        value:
            "Pack",

        semanticType:
            "physical",

        isSystemDefault:
            true
    },

    {
        code:
            "PAIR",

        value:
            "Pair",

        semanticType:
            "physical",

        isSystemDefault:
            true
    },

    {
        code:
            "SET",

        value:
            "Set",

        semanticType:
            "physical",

        isSystemDefault:
            true
    },

    {
        code:
            "UNIT",

        value:
            "Unit",

        semanticType:
            "physical",

        isSystemDefault:
            true
    }

];


// =====================================================
// MONETARY UNIT CODES
// =====================================================

const MONETARY_UNIT_CODES =
    SERVICE_DELIVERY_UNIT_DEFINITIONS
        .filter(
            unit =>
                unit.semanticType ===
                "monetary"
        )
        .map(
            unit =>
                unit.code
        );


// =====================================================
// PHYSICAL UNIT CODES
// =====================================================

const PHYSICAL_UNIT_CODES =
    SERVICE_DELIVERY_UNIT_DEFINITIONS
        .filter(
            unit =>
                unit.semanticType ===
                "physical"
        )
        .map(
            unit =>
                unit.code
        );


// =====================================================
// NORMALIZE UNIT CODE
// =====================================================

const normalizeUnitCode = (
    value
) => {

    if (
        value === undefined ||
        value === null
    ) {

        return "";

    }

    return String(value)
        .trim()
        .toUpperCase();

};


// =====================================================
// CHECK MONETARY UNIT CODE
// =====================================================

const isMonetaryUnitCode = (
    code
) => {

    const normalizedCode =
        normalizeUnitCode(
            code
        );

    return MONETARY_UNIT_CODES.includes(
        normalizedCode
    );

};


// =====================================================
// CHECK PHYSICAL UNIT CODE
// =====================================================

const isPhysicalUnitCode = (
    code
) => {

    const normalizedCode =
        normalizeUnitCode(
            code
        );

    return PHYSICAL_UNIT_CODES.includes(
        normalizedCode
    );

};


// =====================================================
// GET STANDARD UNIT DEFINITION
// =====================================================

const getStandardUnitDefinition = (
    code
) => {

    const normalizedCode =
        normalizeUnitCode(
            code
        );

    return (
        SERVICE_DELIVERY_UNIT_DEFINITIONS
            .find(
                unit =>
                    unit.code ===
                    normalizedCode
            )
        || null
    );

};


// =====================================================
// GET UNIT SEMANTICS
// =====================================================
//
// This function remains available for compatibility
// with existing Service Delivery code.
//
// IMPORTANT:
//
// It should eventually be replaced at runtime by the
// database Lookup semanticType.
//
// This function is now only the STANDARD DEFAULT
// definition fallback.
//
// =====================================================

const getUnitSemantics = (
    code
) => {

    const definition =
        getStandardUnitDefinition(
            code
        );

    if (
        definition
    ) {

        return definition.semanticType;

    }

    return "unknown";

};


// =====================================================
// EXPORT
// =====================================================

// =====================================================
// DECIMAL QUANTITIES
// =====================================================
//
// Weights, volumes and lengths can be measured in parts
// (12.5 Kg, 0.5 Liter); everything else is counted in
// whole numbers (Piece, Set, Pack, Session, ...).
// =====================================================

const DECIMAL_UNIT_CODES = [
    "KG",
    "KILOGRAM",
    "LITER",
    "LITRE",
    "METER"
];

// unit: a Lookup (code / value) or a code string
const allowsDecimalQuantity = (unit) => {

    const candidates =
        typeof unit === "object" && unit !== null
            ? [unit.code, unit.unitCode, unit.lookupCode, unit.value, unit.name]
            : [unit];

    return candidates
        .filter(Boolean)
        .some(candidate => DECIMAL_UNIT_CODES.includes(normalizeUnitCode(candidate)));

};


module.exports = {

    SERVICE_DELIVERY_UNIT_DEFINITIONS,

    DECIMAL_UNIT_CODES,

    allowsDecimalQuantity,

    MONETARY_UNIT_CODES,

    PHYSICAL_UNIT_CODES,

    normalizeUnitCode,

    isMonetaryUnitCode,

    isPhysicalUnitCode,

    getStandardUnitDefinition,

    getUnitSemantics

};