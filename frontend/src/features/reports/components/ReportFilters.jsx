import {
    useEffect,
    useMemo
} from "react";


import {
    Box,
    Typography
} from "@mui/material";


import {
    useDispatch,
    useSelector
} from "react-redux";


import {
    FormSection,
    FormGrid,
    FormActions,
    AppSelect,
    AppDatePicker,
    AppButton
} from "../../../components/ui";


import {
    getReportProgramsThunk,
    getReportProjectsThunk,
    getReportActivitiesThunk,
    getReportActivityRunsThunk,
    getReportEnterprisesThunk
} from "../store/reportThunks";


import {
    setReportFilter,
    clearReportFilters
} from "../store/reportSlice";


// =====================================================
// HELPERS
// =====================================================

const normalizeLookupValue = (
    value
) => {

    if (
        value === undefined ||
        value === null ||
        value === ""
    ) {

        return "";

    }


    if (
        typeof value === "object"
    ) {

        if (
            value?.beneficiary
        ) {

            return normalizeLookupValue(
                value.beneficiary
            );

        }


        return String(
            value?._id ??
            value?.id ??
            value?.value ??
            ""
        );

    }


    return String(
        value
    );

};


// =====================================================
// RELATED ID
// =====================================================

const getRelatedId = (
    item,
    field
) => {

    if (
        !item
    ) {

        return "";

    }


    const directValue =
        item?.[field];


    const directId =
        normalizeLookupValue(
            directValue
        );


    if (
        directId
    ) {

        return directId;

    }


    const fieldId =
        `${field}Id`;


    const fieldID =
        `${field}ID`;


    const snakeFieldId =
        `${field}_id`;


    const variants = [

        item?.[fieldId],

        item?.[fieldID],

        item?.[snakeFieldId]

    ];


    for (
        const value
        of variants
    ) {

        const normalized =
            normalizeLookupValue(
                value
            );


        if (
            normalized
        ) {

            return normalized;

        }

    }


    return "";

};


// =====================================================
// ITEM ID
// =====================================================

const getItemId = (
    item
) => {

    return normalizeLookupValue(
        item
    );

};


// =====================================================
// ITEM LABEL
// =====================================================

const getItemLabel = (
    item
) => {

    if (
        !item
    ) {

        return "";

    }


    if (
        typeof item === "string"
    ) {

        return item;

    }


    const name =
        item.name ||
        item.title ||
        item.programName ||
        item.projectName ||
        item.activityName ||
        item.runName ||
        item.activityRunName ||
        item.enterpriseName ||
        "";


    const code =
        item.programCode ||
        item.projectCode ||
        item.activityCode ||
        item.runCode ||
        item.activityRunCode ||
        item.enterpriseNumber ||
        item.code ||
        "";


    if (
        code &&
        name
    ) {

        return `${code} - ${name}`;

    }


    return (
        name ||
        code ||
        getItemId(
            item
        )
    );

};


// =====================================================
// OPTION BUILDER
// =====================================================

const buildOptions = (
    items = []
) => {

    if (
        !Array.isArray(
            items
        )
    ) {

        return [];

    }


    const seen =
        new Set();


    return items
        .map(
            (
                item
            ) => {

                const value =
                    getItemId(
                        item
                    );


                if (
                    !value
                ) {

                    return null;

                }


                if (
                    seen.has(
                        value
                    )
                ) {

                    return null;

                }


                seen.add(
                    value
                );


                return {

                    value,

                    label:
                        getItemLabel(
                            item
                        )

                };

            }
        )
        .filter(
            Boolean
        );

};


// =====================================================
// COMPONENT
// =====================================================

const ReportFilters = ({
    reportConfig = {}
}) => {

    const dispatch =
        useDispatch();


    const {
        filters = {},

        programs = [],

        projects = [],

        activities = [],

        activityRuns = [],

        enterprises = [],

        filterLoading = false,

        filterError = null
    } =
        useSelector(
            (
                state
            ) =>
                state.reports || {}
        );


    const {
        startDate = null,

        endDate = null,

        program = "",

        project = "",

        activity = "",

        activityRun = "",

        enterprise = ""
    } =
        filters;


    const filterConfig =
        reportConfig?.filters ||
        {};


    const showDateFilters =
        filterConfig.date === true;


    const showProgramFilter =
        filterConfig.program === true;


    const showProjectFilter =
        filterConfig.project === true;


    const showActivityFilter =
        filterConfig.activity === true;


    const showActivityRunFilter =
        filterConfig.activityRun === true;


    const showEnterpriseFilter =
        filterConfig.enterprise === true;


    // =================================================
    // LOAD PROGRAMS
    // =================================================

    useEffect(
        () => {

            if (
                !showProgramFilter
            ) {

                return;

            }


            dispatch(
                getReportProgramsThunk()
            );

        },
        [
            dispatch,
            showProgramFilter
        ]
    );


    // =================================================
    // LOAD PROJECTS
    // =================================================

    useEffect(
        () => {

            if (
                !showProjectFilter
            ) {

                return;

            }


            dispatch(
                getReportProjectsThunk()
            );

        },
        [
            dispatch,
            showProjectFilter
        ]
    );


    // =================================================
    // LOAD ACTIVITIES
    // =================================================

    useEffect(
        () => {

            if (
                !showActivityFilter
            ) {

                return;

            }


            dispatch(
                getReportActivitiesThunk()
            );

        },
        [
            dispatch,
            showActivityFilter
        ]
    );


    // =================================================
    // LOAD ACTIVITY RUNS
    // =================================================

    useEffect(
        () => {

            if (
                !showActivityRunFilter
            ) {

                return;

            }


            dispatch(
                getReportActivityRunsThunk()
            );

        },
        [
            dispatch,
            showActivityRunFilter
        ]
    );


    // =================================================
    // LOAD ENTERPRISES
    // =================================================

    useEffect(
        () => {

            if (
                !showEnterpriseFilter
            ) {

                return;

            }


            dispatch(
                getReportEnterprisesThunk()
            );

        },
        [
            dispatch,
            showEnterpriseFilter
        ]
    );


    // =================================================
    // SELECTED IDS
    // =================================================

    const selectedProgramId =
        normalizeLookupValue(
            program
        );


    const selectedProjectId =
        normalizeLookupValue(
            project
        );


    const selectedActivityId =
        normalizeLookupValue(
            activity
        );


    // =================================================
    // FILTER PROJECTS
    //
    // Program selected:
    //     show projects belonging to program.
    //
    // No program selected:
    //     show all projects.
    // =================================================

    const filteredProjects =
        useMemo(
            () => {

                const availableProjects =
                    Array.isArray(
                        projects
                    )
                        ? projects
                        : [];


                if (
                    !selectedProgramId
                ) {

                    return availableProjects;

                }


                return availableProjects.filter(
                    (
                        projectItem
                    ) => {

                        const projectProgramId =
                            getRelatedId(
                                projectItem,
                                "program"
                            );


                        return (
                            projectProgramId ===
                            selectedProgramId
                        );

                    }
                );

            },
            [
                projects,
                selectedProgramId
            ]
        );


    // =================================================
    // FILTER ACTIVITIES
    //
    // Project selected:
    //     show activities belonging to project.
    //
    // No project but program selected:
    //     show activities belonging to projects
    //     under the selected program.
    //
    // Nothing selected:
    //     show all activities.
    // =================================================

    const filteredActivities =
        useMemo(
            () => {

                const availableActivities =
                    Array.isArray(
                        activities
                    )
                        ? activities
                        : [];


                if (
                    selectedProjectId
                ) {

                    return availableActivities.filter(
                        (
                            activityItem
                        ) => {

                            const activityProjectId =
                                getRelatedId(
                                    activityItem,
                                    "project"
                                );


                            return (
                                activityProjectId ===
                                selectedProjectId
                            );

                        }
                    );

                }


                if (
                    selectedProgramId
                ) {

                    const programProjectIds =
                        new Set(
                            (
                                Array.isArray(
                                    projects
                                )
                                    ? projects
                                    : []
                            )
                                .filter(
                                    (
                                        projectItem
                                    ) =>
                                        getRelatedId(
                                            projectItem,
                                            "program"
                                        ) ===
                                        selectedProgramId
                                )
                                .map(
                                    (
                                        projectItem
                                    ) =>
                                        getItemId(
                                            projectItem
                                        )
                                )
                                .filter(
                                    Boolean
                                )
                        );


                    return availableActivities.filter(
                        (
                            activityItem
                        ) => {

                            const activityProjectId =
                                getRelatedId(
                                    activityItem,
                                    "project"
                                );


                            return programProjectIds.has(
                                activityProjectId
                            );

                        }
                    );

                }


                return availableActivities;

            },
            [
                activities,
                projects,
                selectedProjectId,
                selectedProgramId
            ]
        );


    // =================================================
    // FILTER ACTIVITY RUNS
    //
    // Activity selected:
    //     show runs belonging to activity.
    //
    // Project selected:
    //     show runs belonging to activities under project.
    //
    // Program selected:
    //     show runs belonging to activities under program.
    //
    // Nothing selected:
    //     show all runs.
    // =================================================

    const filteredActivityRuns =
        useMemo(
            () => {

                const availableRuns =
                    Array.isArray(
                        activityRuns
                    )
                        ? activityRuns
                        : [];


                if (
                    selectedActivityId
                ) {

                    return availableRuns.filter(
                        (
                            activityRunItem
                        ) => {

                            const runActivityId =
                                getRelatedId(
                                    activityRunItem,
                                    "activity"
                                );


                            return (
                                runActivityId ===
                                selectedActivityId
                            );

                        }
                    );

                }


                if (
                    selectedProjectId
                ) {

                    const projectActivityIds =
                        new Set(
                            (
                                Array.isArray(
                                    activities
                                )
                                    ? activities
                                    : []
                            )
                                .filter(
                                    (
                                        activityItem
                                    ) =>
                                        getRelatedId(
                                            activityItem,
                                            "project"
                                        ) ===
                                        selectedProjectId
                                )
                                .map(
                                    (
                                        activityItem
                                    ) =>
                                        getItemId(
                                            activityItem
                                        )
                                )
                                .filter(
                                    Boolean
                                )
                        );


                    return availableRuns.filter(
                        (
                            activityRunItem
                        ) => {

                            const runActivityId =
                                getRelatedId(
                                    activityRunItem,
                                    "activity"
                                );


                            return projectActivityIds.has(
                                runActivityId
                            );

                        }
                    );

                }


                if (
                    selectedProgramId
                ) {

                    const programProjectIds =
                        new Set(
                            (
                                Array.isArray(
                                    projects
                                )
                                    ? projects
                                    : []
                            )
                                .filter(
                                    (
                                        projectItem
                                    ) =>
                                        getRelatedId(
                                            projectItem,
                                            "program"
                                        ) ===
                                        selectedProgramId
                                )
                                .map(
                                    (
                                        projectItem
                                    ) =>
                                        getItemId(
                                            projectItem
                                        )
                                )
                                .filter(
                                    Boolean
                                )
                        );


                    const programActivityIds =
                        new Set(
                            (
                                Array.isArray(
                                    activities
                                )
                                    ? activities
                                    : []
                            )
                                .filter(
                                    (
                                        activityItem
                                    ) =>
                                        programProjectIds.has(
                                            getRelatedId(
                                                activityItem,
                                                "project"
                                            )
                                        )
                                )
                                .map(
                                    (
                                        activityItem
                                    ) =>
                                        getItemId(
                                            activityItem
                                        )
                                )
                                .filter(
                                    Boolean
                                )
                        );


                    return availableRuns.filter(
                        (
                            activityRunItem
                        ) => {

                            const runActivityId =
                                getRelatedId(
                                    activityRunItem,
                                    "activity"
                                );


                            return programActivityIds.has(
                                runActivityId
                            );

                        }
                    );

                }


                return availableRuns;

            },
            [
                activityRuns,
                activities,
                projects,
                selectedActivityId,
                selectedProjectId,
                selectedProgramId
            ]
        );


    // =================================================
    // BUILD OPTIONS
    // =================================================

    const programOptions =
        useMemo(
            () =>
                buildOptions(
                    programs
                ),
            [
                programs
            ]
        );


    const projectOptions =
        useMemo(
            () =>
                buildOptions(
                    filteredProjects
                ),
            [
                filteredProjects
            ]
        );


    const activityOptions =
        useMemo(
            () =>
                buildOptions(
                    filteredActivities
                ),
            [
                filteredActivities
            ]
        );


    const activityRunOptions =
        useMemo(
            () =>
                buildOptions(
                    filteredActivityRuns
                ),
            [
                filteredActivityRuns
            ]
        );


    const enterpriseOptions =
        useMemo(
            () =>
                buildOptions(
                    enterprises
                ),
            [
                enterprises
            ]
        );


    // =================================================
    // PROGRAM CHANGE
    // =================================================

    const handleProgramChange =
        (
            event
        ) => {

            const value =
                normalizeLookupValue(
                    event?.target?.value
                );


            dispatch(
                setReportFilter({
                    field:
                        "program",

                    value
                })
            );


            if (
                project &&
                value
            ) {

                const projectStillValid =
                    (
                        Array.isArray(
                            projects
                        )
                            ? projects
                            : []
                    ).some(
                        (
                            projectItem
                        ) =>
                            getItemId(
                                projectItem
                            ) ===
                            selectedProjectId &&
                            getRelatedId(
                                projectItem,
                                "program"
                            ) ===
                            value
                    );


                if (
                    !projectStillValid
                ) {

                    dispatch(
                        setReportFilter({
                            field:
                                "project",

                            value:
                                ""
                        })
                    );


                    dispatch(
                        setReportFilter({
                            field:
                                "activity",

                            value:
                                ""
                        })
                    );


                    dispatch(
                        setReportFilter({
                            field:
                                "activityRun",

                            value:
                                ""
                        })
                    );

                }

            }


            if (
                !value
            ) {

                return;

            }


            if (
                !project
            ) {

                return;

            }


            const projectStillValid =
                (
                    Array.isArray(
                        projects
                    )
                        ? projects
                        : []
                ).some(
                    (
                        projectItem
                    ) =>
                        getItemId(
                            projectItem
                        ) ===
                        selectedProjectId &&
                        getRelatedId(
                            projectItem,
                            "program"
                        ) ===
                        value
                );


            if (
                projectStillValid
            ) {

                return;

            }


            dispatch(
                setReportFilter({
                    field:
                        "project",

                    value:
                        ""
                })
            );


            dispatch(
                setReportFilter({
                    field:
                        "activity",

                    value:
                        ""
                })
            );


            dispatch(
                setReportFilter({
                    field:
                        "activityRun",

                    value:
                        ""
                })
            );

        };


    // =================================================
    // PROJECT CHANGE
    // =================================================

    const handleProjectChange =
        (
            event
        ) => {

            const value =
                normalizeLookupValue(
                    event?.target?.value
                );


            dispatch(
                setReportFilter({
                    field:
                        "project",

                    value
                })
            );


            if (
                activity &&
                value
            ) {

                const activityStillValid =
                    (
                        Array.isArray(
                            activities
                        )
                            ? activities
                            : []
                    ).some(
                        (
                            activityItem
                        ) =>
                            getItemId(
                                activityItem
                            ) ===
                            selectedActivityId &&
                            getRelatedId(
                                activityItem,
                                "project"
                            ) ===
                            value
                    );


                if (
                    !activityStillValid
                ) {

                    dispatch(
                        setReportFilter({
                            field:
                                "activity",

                            value:
                                ""
                        })
                    );


                    dispatch(
                        setReportFilter({
                            field:
                                "activityRun",

                            value:
                                ""
                        })
                    );

                }

            }


            if (
                !value
            ) {

                dispatch(
                    setReportFilter({
                        field:
                            "activity",

                        value:
                            ""
                    })
                );


                dispatch(
                    setReportFilter({
                        field:
                            "activityRun",

                        value:
                            ""
                    })
                );

                return;

            }


            const activityStillValid =
                activity
                    ? (
                        Array.isArray(
                            activities
                        )
                            ? activities
                            : []
                    ).some(
                        (
                            activityItem
                        ) =>
                            getItemId(
                                activityItem
                            ) ===
                            selectedActivityId &&
                            getRelatedId(
                                activityItem,
                                "project"
                            ) ===
                            value
                    )
                    : true;


            if (
                activityStillValid
            ) {

                return;

            }


            dispatch(
                setReportFilter({
                    field:
                        "activity",

                    value:
                        ""
                })
            );


            dispatch(
                setReportFilter({
                    field:
                        "activityRun",

                    value:
                        ""
                })
            );

        };


    // =================================================
    // ACTIVITY CHANGE
    // =================================================

    const handleActivityChange =
        (
            event
        ) => {

            const value =
                normalizeLookupValue(
                    event?.target?.value
                );


            dispatch(
                setReportFilter({
                    field:
                        "activity",

                    value
                })
            );


            if (
                activityRun &&
                value
            ) {

                const runStillValid =
                    (
                        Array.isArray(
                            activityRuns
                        )
                            ? activityRuns
                            : []
                    ).some(
                        (
                            activityRunItem
                        ) =>
                            getItemId(
                                activityRunItem
                            ) ===
                            normalizeLookupValue(
                                activityRun
                            ) &&
                            getRelatedId(
                                activityRunItem,
                                "activity"
                            ) ===
                            value
                    );


                if (
                    !runStillValid
                ) {

                    dispatch(
                        setReportFilter({
                            field:
                                "activityRun",

                            value:
                                ""
                        })
                    );

                }

            }


            if (
                !value
            ) {

                dispatch(
                    setReportFilter({
                        field:
                            "activityRun",

                    value:
                            ""
                    })
                );

            }

        };


    // =================================================
    // ACTIVITY RUN CHANGE
    // =================================================

    const handleActivityRunChange =
        (
            event
        ) => {

            const value =
                normalizeLookupValue(
                    event?.target?.value
                );


            dispatch(
                setReportFilter({
                    field:
                        "activityRun",

                    value
                })
            );

        };


    // =================================================
    // ENTERPRISE CHANGE
    // =================================================

    const handleEnterpriseChange =
        (
            event
        ) => {

            const value =
                normalizeLookupValue(
                    event?.target?.value
                );


            dispatch(
                setReportFilter({
                    field:
                        "enterprise",

                    value
                })
            );

        };


    // =================================================
    // START DATE CHANGE
    // =================================================

    const handleStartDateChange =
        (
            value
        ) => {

            const normalizedDate =
                normalizeReportDate(
                    value
                );


            dispatch(
                setReportFilter({
                    field:
                        "startDate",

                    value:
                        normalizedDate
                })
            );


            if (
                normalizedDate &&
                endDate &&
                normalizedDate >
                String(
                    endDate
                )
            ) {

                dispatch(
                    setReportFilter({
                        field:
                            "endDate",

                        value:
                            null
                    })
                );

            }

        };


    // =================================================
    // END DATE CHANGE
    // =================================================

    const handleEndDateChange =
        (
            value
        ) => {

            const normalizedDate =
                normalizeReportDate(
                    value
                );


            dispatch(
                setReportFilter({
                    field:
                        "endDate",

                    value:
                        normalizedDate
                })
            );

        };


    // =================================================
    // CLEAR FILTERS
    // =================================================

    const handleClearFilters =
        () => {

            dispatch(
                clearReportFilters()
            );

        };


    // =================================================
    // DATE VALIDATION
    // =================================================

    const invalidDateRange =
        Boolean(
            startDate &&
            endDate &&
            String(
                endDate
            ) <
            String(
                startDate
            )
        );


    // =================================================
    // RENDER
    // =================================================

    return (

        <FormSection
            title="Report Filters"
        >

            <Box
                sx={{
                    width: "100%"
                }}
            >

                <FormGrid>

                    {
                        showDateFilters && (

                            <AppDatePicker
                                label="Start Date"
                                value={
                                    startDate
                                }
                                onChange={
                                    handleStartDateChange
                                }
                            />

                        )
                    }


                    {
                        showDateFilters && (

                            <AppDatePicker
                                label="End Date"
                                value={
                                    endDate
                                }
                                onChange={
                                    handleEndDateChange
                                }
                            />

                        )
                    }


                    {
                        showProgramFilter && (

                            <AppSelect
                                label="Program"
                                value={
                                    program
                                }
                                onChange={
                                    handleProgramChange
                                }
                                disabled={
                                    filterLoading
                                }
                                placeholder="All Programs"
                                options={
                                    programOptions
                                }
                            />

                        )
                    }


                    {
                        showProjectFilter && (

                            <AppSelect
                                label="Project"
                                value={
                                    project
                                }
                                onChange={
                                    handleProjectChange
                                }
                                disabled={
                                    filterLoading
                                }
                                placeholder="All Projects"
                                options={
                                    projectOptions
                                }
                            />

                        )
                    }


                    {
                        showActivityFilter && (

                            <AppSelect
                                label="Activity"
                                value={
                                    activity
                                }
                                onChange={
                                    handleActivityChange
                                }
                                disabled={
                                    filterLoading
                                }
                                placeholder="All Activities"
                                options={
                                    activityOptions
                                }
                            />

                        )
                    }


                    {
                        showActivityRunFilter && (

                            <AppSelect
                                label="Activity Run"
                                value={
                                    activityRun
                                }
                                onChange={
                                    handleActivityRunChange
                                }
                                disabled={
                                    filterLoading
                                }
                                placeholder="All Activity Runs"
                                options={
                                    activityRunOptions
                                }
                            />

                        )
                    }


                    {
                        showEnterpriseFilter && (

                            <AppSelect
                                label="Enterprise"
                                value={
                                    enterprise
                                }
                                onChange={
                                    handleEnterpriseChange
                                }
                                disabled={
                                    filterLoading
                                }
                                placeholder="All Enterprises"
                                options={
                                    enterpriseOptions
                                }
                            />

                        )
                    }

                </FormGrid>


                {
                    invalidDateRange && (

                        <Box
                            sx={{
                                mt: 2,
                                px: 1.5,
                                py: 1,
                                borderRadius: 1,
                                backgroundColor:
                                    "error.lighter",
                                border:
                                    "1px solid",
                                borderColor:
                                    "error.light"
                            }}
                        >

                            <Typography
                                variant="body2"
                                color="error.main"
                            >
                                End Date cannot be earlier than Start Date.
                            </Typography>

                        </Box>

                    )
                }


                {
                    filterError && (

                        <Box
                            sx={{
                                mt: 2,
                                px: 1.5,
                                py: 1,
                                borderRadius: 1,
                                backgroundColor:
                                    "error.lighter",
                                border:
                                    "1px solid",
                                borderColor:
                                    "error.light"
                            }}
                        >

                            <Typography
                                variant="body2"
                                color="error.main"
                            >
                                {
                                    filterError
                                }
                            </Typography>

                        </Box>

                    )
                }


                <FormActions>

                    <AppButton
                        variant="outlined"
                        onClick={
                            handleClearFilters
                        }
                        disabled={
                            filterLoading
                        }
                    >
                        Clear Filters
                    </AppButton>

                </FormActions>

            </Box>

        </FormSection>

    );

};


// =====================================================
// REPORT DATE NORMALIZER
// =====================================================

const normalizeReportDate = (
    value
) => {

    if (
        value === undefined ||
        value === null ||
        value === ""
    ) {

        return null;

    }


    if (
        typeof value === "string"
    ) {

        if (
            /^\d{4}-\d{2}-\d{2}$/.test(
                value
            )
        ) {

            return value;

        }


        const parsedDate =
            new Date(
                value
            );


        if (
            Number.isNaN(
                parsedDate.getTime()
            )
        ) {

            return null;

        }


        const year =
            parsedDate.getFullYear();


        const month =
            String(
                parsedDate.getMonth() + 1
            ).padStart(
                2,
                "0"
            );


        const day =
            String(
                parsedDate.getDate()
            ).padStart(
                2,
                "0"
            );


        return `${year}-${month}-${day}`;

    }


    if (
        typeof value?.format ===
        "function"
    ) {

        const formattedDate =
            value.format(
                "YYYY-MM-DD"
            );


        return formattedDate || null;

    }


    return null;

};


export default ReportFilters;