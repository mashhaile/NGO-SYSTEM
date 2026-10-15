import axiosClient from "../../../services/axiosClient";


// =====================================================
// PLATFORM ANALYTICS
// =====================================================

export const getPlatformAnalyticsApi =
    async () => {

        const response =
            await axiosClient.get(
                "/super-admin/analytics"
            );

        return response.data;

    };