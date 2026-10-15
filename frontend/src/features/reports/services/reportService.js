// =====================================================
// REPORT SERVICES
// =====================================================

import {
    getReportsApi,
    generateReportApi,
    exportReportApi
} from "../api/reportApi";


import {
    getProgramsService
} from "../../programs/services/programService";


import {
    getProjectLookupService
} from "../../projects/services/projectService";


import {
    getActivitiesService
} from "../../activities/services/activityService";


import {
    getActivityRunsService
} from "../../activityRuns/services/activityRunService";


import {
    getEnterpriseLookupService
} from "../../enterprise/services/enterpriseService";


// =====================================================
// GET AVAILABLE REPORTS
// =====================================================

export const getReportsService =
    async () => {

        return await getReportsApi();

    };


// =====================================================
// GENERATE REPORT
// =====================================================

export const generateReportService =
    async (
        reportName,
        filters = {}
    ) => {

        return await generateReportApi(
            reportName,
            filters
        );

    };


// =====================================================
// EXPORT REPORT
// =====================================================

export const exportReportService =
    async (
        reportName,
        filters = {},
        format
    ) => {

        return await exportReportApi(
            reportName,
            filters,
            format
        );

    };


// =====================================================
// GET PROGRAMS
// =====================================================

export const getReportProgramsService =
    async () => {

        return await getProgramsService({

            page:
                1,

            limit:
                100

        });

    };


// =====================================================
// GET PROJECTS
// =====================================================

export const getReportProjectsService =
    async () => {

        return await getProjectLookupService();

    };


// =====================================================
// GET ACTIVITIES
// =====================================================

export const getReportActivitiesService =
    async () => {

        return await getActivitiesService({

            page:
                1,

            limit:
                100

        });

    };


// =====================================================
// GET ACTIVITY RUNS
// =====================================================

export const getReportActivityRunsService =
    async () => {

        return await getActivityRunsService({

            page:
                1,

            limit:
                100

        });

    };


// =====================================================
// GET ENTERPRISES
// =====================================================

export const getReportEnterprisesService =
    async () => {

        return await getEnterpriseLookupService();

    };