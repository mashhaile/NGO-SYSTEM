import {
    createOrganizationApi,
    getOrganizationsApi,
    getOrganizationByIdApi,
    updateOrganizationApi,
    activateOrganizationApi,
    suspendOrganizationApi,
    deactivateOrganizationApi,
    restoreOrganizationApi,
    deleteOrganizationApi
} from "../api/organizationApi";


// =====================================================
// CREATE ORGANIZATION
// SUPER ADMIN
// =====================================================

const createOrganizationService = async (
    data
) => {

    return await createOrganizationApi(
        data
    );

};


// =====================================================
// GET ORGANIZATIONS
// SUPER ADMIN
// =====================================================

const getOrganizationsService = async (
    params = {}
) => {

    return await getOrganizationsApi(
        params
    );

};


// =====================================================
// GET ORGANIZATION DETAILS
// SUPER ADMIN
// =====================================================

const getOrganizationByIdService = async (
    id
) => {

    return await getOrganizationByIdApi(
        id
    );

};


// =====================================================
// UPDATE ORGANIZATION
// SUPER ADMIN
// =====================================================

const updateOrganizationService = async (
    id,
    data
) => {

    return await updateOrganizationApi(
        id,
        data
    );

};


// =====================================================
// ACTIVATE ORGANIZATION
// SUPER ADMIN
// =====================================================

const activateOrganizationService = async (
    id
) => {

    return await activateOrganizationApi(
        id
    );

};


// =====================================================
// SUSPEND ORGANIZATION
// SUPER ADMIN
// =====================================================

const suspendOrganizationService = async (
    id
) => {

    return await suspendOrganizationApi(
        id
    );

};


// =====================================================
// DEACTIVATE ORGANIZATION
// SUPER ADMIN
// =====================================================

const deactivateOrganizationService = async (
    id
) => {

    return await deactivateOrganizationApi(
        id
    );

};


// =====================================================
// RESTORE ORGANIZATION
// SUPER ADMIN
// =====================================================

const restoreOrganizationService = async (
    id
) => {

    return await restoreOrganizationApi(
        id
    );

};


// =====================================================
// DELETE ORGANIZATION
// SUPER ADMIN
// =====================================================

const deleteOrganizationService = async (
    id
) => {

    return await deleteOrganizationApi(
        id
    );

};


// =====================================================
// EXPORTS
// =====================================================

export {

    createOrganizationService,

    getOrganizationsService,

    getOrganizationByIdService,

    updateOrganizationService,

    activateOrganizationService,

    suspendOrganizationService,

    deactivateOrganizationService,

    restoreOrganizationService,

    deleteOrganizationService

};


export default {

    createOrganizationService,

    getOrganizationsService,

    getOrganizationByIdService,

    updateOrganizationService,

    activateOrganizationService,

    suspendOrganizationService,

    deactivateOrganizationService,

    restoreOrganizationService,

    deleteOrganizationService

};
