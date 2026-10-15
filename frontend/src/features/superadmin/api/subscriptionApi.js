import axiosClient from "../../../services/axiosClient";


// =====================================================
// PLANS
// =====================================================

// GET ACTIVE / PUBLIC PLANS

export const getActivePlansApi =
    async () => {

        const response =
            await axiosClient.get(
                "/plans/public"
            );

        return response.data;

    };


// GET ALL PLANS
// SUPER ADMIN ONLY

export const getAllPlansApi =
    async () => {

        const response =
            await axiosClient.get(
                "/plans"
            );

        return response.data;

    };


// GET PLAN BY ID
// SUPER ADMIN ONLY

export const getPlanByIdApi =
    async (
        id
    ) => {

        const response =
            await axiosClient.get(
                `/plans/${id}`
            );

        return response.data;

    };


// CREATE PLAN
// SUPER ADMIN ONLY

export const createPlanApi =
    async (
        data
    ) => {

        const response =
            await axiosClient.post(
                "/plans",
                data
            );

        return response.data;

    };


// UPDATE PLAN
// SUPER ADMIN ONLY

export const updatePlanApi =
    async (
        id,
        data
    ) => {

        const response =
            await axiosClient.put(
                `/plans/${id}`,
                data
            );

        return response.data;

    };


// ACTIVATE PLAN
// SUPER ADMIN ONLY

export const activatePlanApi =
    async (
        id
    ) => {

        const response =
            await axiosClient.put(
                `/plans/${id}/activate`
            );

        return response.data;

    };


// DEACTIVATE PLAN
// SUPER ADMIN ONLY

export const deactivatePlanApi =
    async (
        id
    ) => {

        const response =
            await axiosClient.put(
                `/plans/${id}/deactivate`
            );

        return response.data;

    };


// UPDATE PLAN VISIBILITY
// SUPER ADMIN ONLY

export const updatePlanVisibilityApi =
    async (
        id,
        isPublic
    ) => {

        const response =
            await axiosClient.put(
                `/plans/${id}/visibility`,
                {
                    isPublic
                }
            );

        return response.data;

    };


// =====================================================
// SUPER ADMIN - SUBSCRIPTION MANAGEMENT
// =====================================================

// ASSIGN SUBSCRIPTION

export const assignSubscriptionApi =
    async (
        data
    ) => {

        const response =
            await axiosClient.post(
                "/subscriptions/assign",
                data
            );

        return response.data;

    };


// CHANGE PLAN

export const changePlanApi =
    async (
        organizationId,
        data
    ) => {

        const response =
            await axiosClient.put(
                `/subscriptions/change/${organizationId}`,
                data
            );

        return response.data;

    };


// RENEW SUBSCRIPTION

export const renewSubscriptionApi =
    async (
        organizationId,
        data = {}
    ) => {

        const response =
            await axiosClient.put(
                `/subscriptions/renew/${organizationId}`,
                data
            );

        return response.data;

    };


// CANCEL SUBSCRIPTION

export const cancelSubscriptionApi =
    async (
        organizationId,
        data = {}
    ) => {

        const response =
            await axiosClient.put(
                `/subscriptions/cancel/${organizationId}`,
                data
            );

        return response.data;

    };


// =====================================================
// CURRENT ORGANIZATION SUBSCRIPTION
// =====================================================

// GET CURRENT SUBSCRIPTION

export const getCurrentSubscriptionApi =
    async () => {

        const response =
            await axiosClient.get(
                "/subscriptions/current"
            );

        return response.data;

    };


// =====================================================
// SUBSCRIPTION SUMMARY
// =====================================================

export const getSubscriptionSummaryApi =
    async () => {

        const response =
            await axiosClient.get(
                "/subscriptions/summary"
            );

        return response.data;

    };


// =====================================================
// SUBSCRIPTION FEATURES
// =====================================================

export const getSubscriptionFeaturesApi =
    async () => {

        const response =
            await axiosClient.get(
                "/subscriptions/features"
            );

        return response.data;

    };


// =====================================================
// SUBSCRIPTION LIMITS
// =====================================================

export const getSubscriptionLimitsApi =
    async () => {

        const response =
            await axiosClient.get(
                "/subscriptions/limits"
            );

        return response.data;

    };


// =====================================================
// SUBSCRIPTION USAGE
// =====================================================

export const getSubscriptionUsageApi =
    async () => {

        const response =
            await axiosClient.get(
                "/subscriptions/usage"
            );

        return response.data;

    };


// =====================================================
// SUPER ADMIN - ORGANIZATION SUBSCRIPTION
// =====================================================

// GET ORGANIZATION SUBSCRIPTION

export const getOrganizationSubscriptionApi =
    async (
        organizationId
    ) => {

        const response =
            await axiosClient.get(
                `/subscriptions/organization/${organizationId}`
            );

        return response.data;

    };


// =====================================================
// SUPER ADMIN - ORGANIZATION SUBSCRIPTION USAGE
// =====================================================

// GET ORGANIZATION SUBSCRIPTION USAGE

export const getOrganizationSubscriptionUsageApi =
    async (
        organizationId
    ) => {

        const response =
            await axiosClient.get(
                `/subscriptions/organization/${organizationId}/usage`
            );

        return response.data;

    };
