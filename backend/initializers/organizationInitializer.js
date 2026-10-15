const {
    ensureOrganizationServiceDeliveryUnits
} =
    require("../services/serviceDeliveryUnitService");


// =====================================================
// INITIALIZE ORGANIZATION
// =====================================================
//
// Organization initialization is idempotent.
//
// This function can safely be called:
//
// 1. During new organization creation.
// 2. During existing organization initialization.
// 3. During organization repair/backfill.
//
// Service Delivery Unit creation and repair are handled
// exclusively by serviceDeliveryUnitService.js.
//
// That service is responsible for:
//
// - Creating missing standard units.
// - Preserving existing units.
// - Preserving custom organization units.
// - Preserving inactive units.
// - Repairing missing semanticType on system defaults.
// - Preventing duplicate standard units.
//
// =====================================================

const initializeOrganization = async (
    organizationId,
    userId = null
) => {


    console.log(
    "[ORGANIZATION INITIALIZER] RUNNING FOR:",
    organizationId
);

    if (!organizationId) {

        throw new Error(
            "Organization is required."
        );

    }


    await ensureOrganizationServiceDeliveryUnits(

        organizationId,

        userId

    );

};


// =====================================================
// CREATE DEFAULT LOOKUPS
// =====================================================
//
// Backward-compatible wrapper.
//
// Existing code may call:
//
//     createDefaultLookups()
//
// The actual initialization is delegated to
// initializeOrganization().
//
// =====================================================

const createDefaultLookups = async (
    organizationId,
    userId = null
) => {

    return initializeOrganization(

        organizationId,

        userId

    );

};


// =====================================================
// CREATE DEFAULT SERVICE DELIVERY UNITS
// =====================================================
//
// Backward-compatible wrapper.
//
// The actual Service Delivery Unit implementation lives
// in serviceDeliveryUnitService.js.
//
// =====================================================

const createDefaultServiceDeliveryUnits = async (
    organizationId,
    userId = null
) => {

    if (!organizationId) {

        throw new Error(
            "Organization is required."
        );

    }


    return ensureOrganizationServiceDeliveryUnits(

        organizationId,

        userId

    );

};


// =====================================================
// EXPORTS
// =====================================================

module.exports = {

    initializeOrganization,

    createDefaultLookups,

    createDefaultServiceDeliveryUnits

};
