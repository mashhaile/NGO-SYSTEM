import {
    useEffect,
    useState
} from "react";


import {
    useParams,
    useNavigate
} from "react-router-dom";


import {
    useDispatch
} from "react-redux";


import {
    Edit
} from "@mui/icons-material";


import {
    PageContainer,
    PageHeader,
    PageCard,
    FormSection,
    InfoRow,
    AppButton,
    StatusChip,
    LoadingState
} from "../../../components/ui";


import {
    getActivityRunByIdThunk
} from "../store";


import useZoneLabel
    from "../../locations/hooks/useZoneLabel";
import { formatDate, formatDateTime } from "../../../utils/date";



// =====================================================
// FORMATTERS
// =====================================================


const formatCodeName = (item, codeKey) =>
    item && typeof item === "object"
        ? [item[codeKey], item.name]
            .filter(Boolean)
            .join(" - ")
        : "-";



// =====================================================
// ACTIVITY RUN DETAILS PAGE
// =====================================================

const ActivityRunDetailsPage = () => {

    const {
        id
    } = useParams();

    const navigate =
        useNavigate();

    const dispatch =
        useDispatch();

    const [run, setRun] =
        useState(null);

    const [loading, setLoading] =
        useState(true);

    const [error, setError] =
        useState("");

    const zoneLabel =
        useZoneLabel(
            run?.regionCode
        );


    // =================================================
    // LOAD
    // =================================================

    useEffect(() => {

        let cancelled = false;

        dispatch(
            getActivityRunByIdThunk(id)
        )
            .unwrap()

            .then(data => {

                if (!cancelled) {
                    setRun(data);
                }

            })

            .catch(loadError => {

                console.error(loadError);

                if (!cancelled) {
                    setError(
                        loadError?.message ||
                        (typeof loadError === "string" ? loadError : "") ||
                        "Failed to load activity run"
                    );
                }

            })

            .finally(() => {

                if (!cancelled) {
                    setLoading(false);
                }

            });

        return () => {
            cancelled = true;
        };

    }, [dispatch, id]);


    const backButton = (

        <AppButton
            variant="outlined"
            onClick={() =>
                navigate("/activity-runs")
            }
            sx={{
                mt: 3,
                mb: 5
            }}
        >
            Back to Activity Runs
        </AppButton>

    );


    // =================================================
    // LOADING
    // =================================================

    if (loading) {

        return (

            <PageContainer>

                <PageHeader
                    title="Activity Run Details"
                    subtitle="Loading activity run information"
                />

                <LoadingState
                    message="Loading activity run..."
                />

            </PageContainer>

        );

    }


    // =================================================
    // NOT FOUND
    // =================================================

    if (error || !run) {

        return (

            <PageContainer>

                <PageHeader
                    title="Activity Run Details"
                    subtitle="Activity run record could not be found."
                />

                <PageCard>

                    <FormSection
                        title="Record Not Found"
                    >

                        <InfoRow
                            label="Activity Run"
                            value={
                                error ||
                                "No activity run information available."
                            }
                        />

                    </FormSection>

                </PageCard>

                {backButton}

            </PageContainer>

        );

    }


    // =================================================
    // PAGE
    // =================================================

    return (

        <PageContainer>

            <PageHeader
                title="Activity Run Details"
                subtitle={
                    run.runCode ||
                    "Activity run record"
                }
            />


            {/* ACTIONS */}

            <PageCard>

                <FormSection>

                    <AppButton
                        variant="contained"
                        startIcon={<Edit />}
                        onClick={() =>
                            navigate(
                                `/activity-runs/${id}/edit`
                            )
                        }
                    >
                        Edit Activity Run
                    </AppButton>

                </FormSection>

            </PageCard>


            {/* RUN */}

            <PageCard>

                <FormSection
                    title="Run Information"
                >

                    <InfoRow
                        label="Run Code"
                        value={run.runCode}
                    />

                    <InfoRow
                        label="Run Name"
                        value={run.name}
                    />

                    <InfoRow
                        label="Activity"
                        value={
                            formatCodeName(
                                run.activity,
                                "activityCode"
                            )
                        }
                    />

                    <InfoRow
                        label="Project"
                        value={
                            formatCodeName(
                                run.project,
                                "projectCode"
                            )
                        }
                    />

                    <InfoRow
                        label="Program"
                        value={
                            formatCodeName(
                                run.program,
                                "programCode"
                            )
                        }
                    />

                    <InfoRow
                        label="Trainer"
                        value={
                            run.trainer?.name ||
                            run.trainer?.email ||
                            "-"
                        }
                    />

                    <InfoRow
                        label="Target Group"
                        value={run.targetGroup}
                    />

                </FormSection>

            </PageCard>


            {/* SCHEDULE AND LOCATION */}

            <PageCard>

                <FormSection
                    title="Schedule and Location"
                >

                    <InfoRow
                        label="Start Date"
                        value={
                            formatDate(
                                run.startDate
                            )
                        }
                    />

                    <InfoRow
                        label="End Date"
                        value={
                            formatDate(
                                run.endDate
                            )
                        }
                    />

                    <InfoRow
                        label="Region"
                        value={run.region}
                    />

                    <InfoRow
                        label={zoneLabel}
                        value={run.zone}
                    />

                    <InfoRow
                        label="Woreda"
                        value={run.woreda}
                    />

                    <InfoRow
                        label="Venue / Site"
                        value={run.location}
                    />

                </FormSection>

            </PageCard>


            {/* RECORD */}

            <PageCard>

                <FormSection
                    title="Record Information"
                >

                    <InfoRow
                        label="Status"
                        value={
                            <StatusChip
                                status={run.status}
                            />
                        }
                    />

                    <InfoRow
                        label="Notes"
                        value={run.notes}
                    />

                    <InfoRow
                        label="Created At"
                        value={
                            formatDateTime(
                                run.createdAt
                            )
                        }
                    />

                    <InfoRow
                        label="Updated At"
                        value={
                            formatDateTime(
                                run.updatedAt
                            )
                        }
                    />

                </FormSection>

            </PageCard>


            {backButton}

        </PageContainer>

    );

};


export default ActivityRunDetailsPage;
