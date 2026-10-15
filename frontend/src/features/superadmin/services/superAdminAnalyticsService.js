import {
    getPlatformAnalyticsApi
} from "../api/superAdminAnalyticsApi";


// =====================================================
// PLATFORM ANALYTICS
// =====================================================

export const getPlatformAnalyticsService =
    async () => {

        return await getPlatformAnalyticsApi();

    };


// =====================================================
// DEFAULT EXPORT
// =====================================================

export default {

    getPlatformAnalyticsService

};