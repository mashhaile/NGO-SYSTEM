import axiosClient
    from "../../../services/axiosClient";


// =====================================================
// GET AVAILABLE REPORTS
// =====================================================

export const getReportsApi =
    async () => {

        const response =
            await axiosClient.get(
                "/reports"
            );

        return response.data;

    };


// =====================================================
// GENERATE REPORT
// =====================================================

export const generateReportApi =
    async (
        reportName,
        filters = {}
    ) => {

        const response =
            await axiosClient.get(
                `/reports/${reportName}`,
                {
                    params: {
                        ...filters,
                        format: "json"
                    }
                }
            );

        return response.data;

    };


// =====================================================
// EXPORT REPORT
// =====================================================

export const exportReportApi =
    async (
        reportName,
        filters = {},
        format
    ) => {

        const response =
            await axiosClient.get(
                `/reports/${reportName}`,
                {
                    params: {
                        ...filters,
                        format
                    },

                    responseType:
                        "blob"
                }
            );

        return response;

    };