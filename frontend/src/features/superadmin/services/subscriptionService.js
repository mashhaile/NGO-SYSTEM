import {
    getActivePlansApi,
    getAllPlansApi,
    createPlanApi,
    updatePlanApi,

    assignSubscriptionApi,
    changePlanApi,
    renewSubscriptionApi,
    cancelSubscriptionApi,

    getCurrentSubscriptionApi,
    getSubscriptionSummaryApi,
    getSubscriptionFeaturesApi,
    getSubscriptionLimitsApi,
    getSubscriptionUsageApi,

    getOrganizationSubscriptionApi,
    getOrganizationSubscriptionUsageApi

} from "../api/subscriptionApi";


// =====================================================
// PLANS
// =====================================================

export const getActivePlansService = async () => {

    return await getActivePlansApi();

};


export const getAllPlansService = async () => {

    return await getAllPlansApi();

};


export const createPlanService = async (
    data
) => {

    return await createPlanApi(
        data
    );

};


export const updatePlanService = async (
    id,
    data
) => {

    return await updatePlanApi(
        id,
        data
    );

};


// =====================================================
// SUPER ADMIN - SUBSCRIPTION MANAGEMENT
// =====================================================

export const assignSubscriptionService = async (
    data
) => {

    return await assignSubscriptionApi(
        data
    );

};


export const changePlanService = async (
    organizationId,
    data
) => {

    return await changePlanApi(
        organizationId,
        data
    );

};


export const renewSubscriptionService = async (
    organizationId,
    data = {}
) => {

    return await renewSubscriptionApi(
        organizationId,
        data
    );

};


export const cancelSubscriptionService = async (
    organizationId,
    data = {}
) => {

    return await cancelSubscriptionApi(
        organizationId,
        data
    );

};


// =====================================================
// SUPER ADMIN - ORGANIZATION SUBSCRIPTION
// =====================================================

export const getOrganizationSubscriptionService =
    async (
        organizationId
    ) => {

        return await getOrganizationSubscriptionApi(
            organizationId
        );

    };


export const getOrganizationSubscriptionUsageService =
    async (
        organizationId
    ) => {

        return await getOrganizationSubscriptionUsageApi(
            organizationId
        );

    };


// =====================================================
// CURRENT ORGANIZATION SUBSCRIPTION
// =====================================================

export const getCurrentSubscriptionService =
    async () => {

        return await getCurrentSubscriptionApi();

    };


// =====================================================
// SUBSCRIPTION SUMMARY
// =====================================================

export const getSubscriptionSummaryService =
    async () => {

        return await getSubscriptionSummaryApi();

    };


// =====================================================
// SUBSCRIPTION FEATURES
// =====================================================

export const getSubscriptionFeaturesService =
    async () => {

        return await getSubscriptionFeaturesApi();

    };


// =====================================================
// SUBSCRIPTION LIMITS
// =====================================================

export const getSubscriptionLimitsService =
    async () => {

        return await getSubscriptionLimitsApi();

    };


// =====================================================
// SUBSCRIPTION USAGE
// =====================================================

export const getSubscriptionUsageService =
    async () => {

        return await getSubscriptionUsageApi();

    };


// =====================================================
// DEFAULT EXPORT
// =====================================================

export default {

    getActivePlansService,
    getAllPlansService,
    createPlanService,
    updatePlanService,

    assignSubscriptionService,
    changePlanService,
    renewSubscriptionService,
    cancelSubscriptionService,

    getOrganizationSubscriptionService,
    getOrganizationSubscriptionUsageService,

    getCurrentSubscriptionService,
    getSubscriptionSummaryService,
    getSubscriptionFeaturesService,
    getSubscriptionLimitsService,
    getSubscriptionUsageService

};