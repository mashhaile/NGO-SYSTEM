import {
    currentFiscalYear
} from "../../../utils/fiscalYear";

import {
    createSlice
} from "@reduxjs/toolkit";


import {
    getReportsThunk,
    generateReportThunk,
    getReportProgramsThunk,
    getReportProjectsThunk,
    getReportActivitiesThunk,
    getReportActivityRunsThunk,
    getReportEnterprisesThunk
} from "./reportThunks";


// =====================================================
// INITIAL FILTERS
// =====================================================

// Reports open on the current fiscal year (Jan-Dec) so a
// report can be generated without picking dates first.
const thisYear = currentFiscalYear();

const initialFilters = {

    startDate:
        `${thisYear}-01-01`,

    endDate:
        `${thisYear}-12-31`,

    program:
        "",

    project:
        "",

    activity:
        "",

    activityRun:
        "",

    enterprise:
        "",

    // location cascade (codes are sent as filters)

    region:
        "",

    regionCode:
        "",

    zone:
        "",

    zoneCode:
        "",

    woreda:
        "",

    woredaCode:
        ""

};


// =====================================================
// INITIAL STATE
// =====================================================

const initialState = {

    // =============================================
    // REPORTS
    // =============================================

    reports: [],

    selectedReport:
        null,

    reportData:
        null,


    // =============================================
    // REPORT FILTERS
    // =============================================

    filters: {
        ...initialFilters
    },


    // =============================================
    // FILTER DATA
    // =============================================

    programs: [],

    projects: [],

    activities: [],

    activityRuns: [],

    enterprises: [],


    // =============================================
    // LOADING
    // =============================================

    loading:
        false,

    reportLoading:
        false,

    filterLoading:
        false,


    // =============================================
    // ERRORS
    // =============================================

    error:
        null,

    reportError:
        null,

    filterError:
        null,


    // =============================================
    // SUCCESS
    // =============================================

    successMessage:
        null

};


// =====================================================
// SLICE
// =====================================================

const reportSlice =
    createSlice({

        name:
            "reports",

        initialState,


        reducers: {


            // =============================================
            // SELECT REPORT
            // =============================================

            setSelectedReport: (
                state,
                action
            ) => {

                state.selectedReport =
                    action.payload;

            },


            // =============================================
            // SET REPORT FILTER
            // =============================================

            setReportFilter: (
                state,
                action
            ) => {

                const {
                    field,
                    value
                } =
                    action.payload || {};


                if (
                    !field
                ) {

                    return;

                }


                if (
                    Object.prototype.hasOwnProperty.call(
                        state.filters,
                        field
                    )
                ) {

                    state.filters[field] =
                        value;

                }

            },


            // =============================================
            // CLEAR REPORT FILTERS
            // =============================================
            //
            // IMPORTANT:
            //
            // This clears only the user's selected
            // filter values.
            //
            // It does NOT clear programs, projects,
            // activities, activity runs, or enterprises.
            //
            // Those are lookup datasets, not filter values.
            //
            // This is important when switching:
            //
            // Beneficiary Report
            //        ↓
            // Beneficiary History Report
            //
            // because ReportFilters does not reload its
            // lookup effects simply because the report
            // changed.
            //
            // =============================================

            clearReportFilters: (
                state
            ) => {

                state.filters = {

                    ...initialFilters

                };

                state.filterError =
                    null;

            },


            // =============================================
            // CLEAR REPORT
            // =============================================

            clearReport: (
                state
            ) => {

                state.reportData =
                    null;

                state.reportError =
                    null;

                state.successMessage =
                    null;

            },


            // =============================================
            // CLEAR MESSAGES
            // =============================================

            clearReportMessage: (
                state
            ) => {

                state.successMessage =
                    null;

                state.error =
                    null;

                state.reportError =
                    null;

                state.filterError =
                    null;

            },


            // =============================================
            // RESET STATE
            // =============================================

            resetReportState: (
                state
            ) => {

                state.reports =
                    [];

                state.selectedReport =
                    null;

                state.reportData =
                    null;


                state.filters = {

                    ...initialFilters

                };


                state.programs =
                    [];

                state.projects =
                    [];

                state.activities =
                    [];

                state.activityRuns =
                    [];

                state.enterprises =
                    [];


                state.loading =
                    false;

                state.reportLoading =
                    false;

                state.filterLoading =
                    false;


                state.error =
                    null;

                state.reportError =
                    null;

                state.filterError =
                    null;

                state.successMessage =
                    null;

            }

        },


        // =================================================
        // EXTRA REDUCERS
        // =================================================

        extraReducers: (
            builder
        ) => {


            // =================================================
            // GET AVAILABLE REPORTS
            // =================================================

            builder.addCase(
                getReportsThunk.pending,
                (
                    state
                ) => {

                    state.loading =
                        true;

                    state.error =
                        null;

                }
            );


            builder.addCase(
                getReportsThunk.fulfilled,
                (
                    state,
                    action
                ) => {



                    const result =
                        action.payload?.data;




                    state.loading =
                        false;

                    state.reports =
                        Array.isArray(
                            result
                        )
                            ? result
                            : [];

                }
            );


            builder.addCase(
                getReportsThunk.rejected,
                (
                    state,
                    action
                ) => {

                    state.loading =
                        false;

                    state.error =
                        action.payload ||
                        "Failed loading reports";

                }
            );


            // =================================================
            // GENERATE REPORT
            // =================================================

            builder.addCase(
                generateReportThunk.pending,
                (
                    state
                ) => {

                    state.reportLoading =
                        true;

                    state.reportError =
                        null;

                    state.successMessage =
                        null;

                }
            );


            builder.addCase(
                generateReportThunk.fulfilled,
                (
                    state,
                    action
                ) => {

                    state.reportLoading =
                        false;

                    state.reportData =
                        action.payload?.data ||
                        null;

                    state.successMessage =
                        "Report generated successfully";

                }
            );


            builder.addCase(
                generateReportThunk.rejected,
                (
                    state,
                    action
                ) => {

                    state.reportLoading =
                        false;

                    state.reportError =
                        action.payload ||
                        "Failed generating report";

                }
            );


            // =================================================
            // GET PROGRAMS
            // =================================================

            builder.addCase(
                getReportProgramsThunk.pending,
                (
                    state
                ) => {

                    state.filterLoading =
                        true;

                    state.filterError =
                        null;

                }
            );


            builder.addCase(
                getReportProgramsThunk.fulfilled,
                (
                    state,
                    action
                ) => {

                    state.filterLoading =
                        false;

                    state.programs =
                        Array.isArray(
                            action.payload
                        )
                            ? action.payload
                            : [];

                }
            );


            builder.addCase(
                getReportProgramsThunk.rejected,
                (
                    state,
                    action
                ) => {

                    state.filterLoading =
                        false;

                    state.filterError =
                        action.payload ||
                        "Failed loading report programs";

                }
            );


            // =================================================
            // GET PROJECTS
            // =================================================

            builder.addCase(
                getReportProjectsThunk.pending,
                (
                    state
                ) => {

                    state.filterLoading =
                        true;

                    state.filterError =
                        null;

                    state.projects =
                        [];

                    state.activities =
                        [];

                    state.activityRuns =
                        [];

                }
            );


            builder.addCase(
                getReportProjectsThunk.fulfilled,
                (
                    state,
                    action
                ) => {

                    state.filterLoading =
                        false;

                    state.projects =
                        Array.isArray(
                            action.payload
                        )
                            ? action.payload
                            : [];

                }
            );


            builder.addCase(
                getReportProjectsThunk.rejected,
                (
                    state,
                    action
                ) => {

                    state.filterLoading =
                        false;

                    state.filterError =
                        action.payload ||
                        "Failed loading report projects";

                }
            );


            // =================================================
            // GET ACTIVITIES
            // =================================================

            builder.addCase(
                getReportActivitiesThunk.pending,
                (
                    state
                ) => {

                    state.filterLoading =
                        true;

                    state.filterError =
                        null;

                    state.activities =
                        [];

                    state.activityRuns =
                        [];

                }
            );


            builder.addCase(
                getReportActivitiesThunk.fulfilled,
                (
                    state,
                    action
                ) => {

                    state.filterLoading =
                        false;

                    state.activities =
                        Array.isArray(
                            action.payload
                        )
                            ? action.payload
                            : [];

                }
            );


            builder.addCase(
                getReportActivitiesThunk.rejected,
                (
                    state,
                    action
                ) => {

                    state.filterLoading =
                        false;

                    state.filterError =
                        action.payload ||
                        "Failed loading report activities";

                }
            );


            // =================================================
            // GET ACTIVITY RUNS
            // =================================================

            builder.addCase(
                getReportActivityRunsThunk.pending,
                (
                    state
                ) => {

                    state.filterLoading =
                        true;

                    state.filterError =
                        null;

                    state.activityRuns =
                        [];

                }
            );


            builder.addCase(
                getReportActivityRunsThunk.fulfilled,
                (
                    state,
                    action
                ) => {

                    state.filterLoading =
                        false;

                    state.activityRuns =
                        Array.isArray(
                            action.payload
                        )
                            ? action.payload
                            : [];

                }
            );


            builder.addCase(
                getReportActivityRunsThunk.rejected,
                (
                    state,
                    action
                ) => {

                    state.filterLoading =
                        false;

                    state.filterError =
                        action.payload ||
                        "Failed loading report activity runs";

                }
            );


            // =================================================
            // GET ENTERPRISES
            // =================================================

            builder.addCase(
                getReportEnterprisesThunk.pending,
                (
                    state
                ) => {

                    state.filterLoading =
                        true;

                    state.filterError =
                        null;

                }
            );


            builder.addCase(
                getReportEnterprisesThunk.fulfilled,
                (
                    state,
                    action
                ) => {

                    state.filterLoading =
                        false;

                    state.enterprises =
                        Array.isArray(
                            action.payload
                        )
                            ? action.payload
                            : [];

                }
            );


            builder.addCase(
                getReportEnterprisesThunk.rejected,
                (
                    state,
                    action
                ) => {

                    state.filterLoading =
                        false;

                    state.filterError =
                        action.payload ||
                        "Failed loading report enterprises";

                }
            );

        }

    });


// =====================================================
// ACTIONS
// =====================================================

export const {
    setSelectedReport,
    setReportFilter,
    clearReportFilters,
    clearReport,
    clearReportMessage,
    resetReportState
} =
    reportSlice.actions;


// =====================================================
// REDUCER
// =====================================================

export default reportSlice.reducer;