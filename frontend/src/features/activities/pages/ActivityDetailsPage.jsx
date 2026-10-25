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
    Chip,
    Link,
    Stack
} from "@mui/material";


import {
    Edit,
    Delete
} from "@mui/icons-material";


import {
    PageContainer,
    PageHeader,
    PageCard,
    FormSection,
    InfoRow,
    AppButton,
    StatusChip,
    LoadingState,
    ConfirmDeleteDialog
} from "../../../components/ui";


import {
    deleteActivityThunk
} from "../store";


import {
    getActivityByIdService
} from "../services/activityService";


import useZoneLabel
    from "../../locations/hooks/useZoneLabel";


import useAuth
    from "../../auth/hooks/useAuth";


import {
    getTorsApi
} from "../../tor/api/torApi";


import {
    hasPermission
} from "../../tor/utils/torPermissions";
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
// ACTIVITY DETAILS PAGE
// =====================================================

const ActivityDetailsPage = () => {

    const {
        id
    } = useParams();

    const navigate =
        useNavigate();

    const dispatch =
        useDispatch();

    const [activity, setActivity] =
        useState(null);

    const [loading, setLoading] =
        useState(true);

    const [error, setError] =
        useState("");

    const [openDelete, setOpenDelete] =
        useState(false);

    const zoneLabel =
        useZoneLabel(
            activity?.regionCode
        );

    const {
        user
    } = useAuth();

    const canReadTors =
        hasPermission(
            user,
            "tor.read"
        );

    // TORs this activity was created from / linked to

    const [tors, setTors] =
        useState([]);

    useEffect(() => {

        if (!canReadTors) {
            return undefined;
        }

        let cancelled = false;

        getTorsApi({
            activity: id,
            limit: 10
        })

            .then(response => {
                if (!cancelled) {
                    setTors(response.data || []);
                }
            })

            .catch(() => {});

        return () => {
            cancelled = true;
        };

    }, [id, canReadTors]);


    // =================================================
    // LOAD
    // =================================================

    useEffect(() => {

        let cancelled = false;

        getActivityByIdService(id)

            .then(response => {

                if (!cancelled) {
                    setActivity(
                        response?.data?.data ||
                        response?.data ||
                        response
                    );
                }

            })

            .catch(loadError => {

                if (!cancelled) {
                    setError(
                        loadError.response?.data?.message ||
                        "Failed to load activity"
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

    }, [id]);


    // =================================================
    // DELETE
    // =================================================

    const handleDelete = async () => {

        await dispatch(
            deleteActivityThunk(id)
        ).unwrap();

        navigate("/activities");

    };


    const backButton = (

        <AppButton
            variant="outlined"
            onClick={() =>
                navigate("/activities")
            }
            sx={{
                mt: 3,
                mb: 5
            }}
        >
            Back to Activities
        </AppButton>

    );


    // =================================================
    // LOADING
    // =================================================

    if (loading) {

        return (

            <PageContainer>

                <PageHeader
                    title="Activity Details"
                    subtitle="Loading activity information"
                />

                <LoadingState
                    message="Loading activity..."
                />

            </PageContainer>

        );

    }


    // =================================================
    // NOT FOUND
    // =================================================

    if (error || !activity) {

        return (

            <PageContainer>

                <PageHeader
                    title="Activity Details"
                    subtitle="Activity record could not be found."
                />

                <PageCard>

                    <FormSection
                        title="Record Not Found"
                    >

                        <InfoRow
                            label="Activity"
                            value={
                                error ||
                                "No activity information available."
                            }
                        />

                    </FormSection>

                </PageCard>

                {backButton}

            </PageContainer>

        );

    }


    const targetGroups =
        activity.targetGroups || [];


    // =================================================
    // PAGE
    // =================================================

    return (
        <PageContainer>

            <PageHeader
                title="Activity Details"
                subtitle={
                    activity.activityCode ||
                    "Activity record"
                }
            />

            {/* ACTIONS */}

            <PageCard>

                <FormSection>

                    <Stack
                        direction={{
                            xs: "column",
                            sm: "row"
                        }}
                        spacing={1.5}
                    >

                        <AppButton
                            variant="contained"
                            startIcon={<Edit />}
                            onClick={() =>
                                navigate(
                                    `/activities/${id}/edit`
                                )
                            }
                        >
                            Edit Activity
                        </AppButton>

                        <AppButton
                            variant="outlined"
                            color="error"
                            startIcon={<Delete />}
                            onClick={() =>
                                setOpenDelete(true)
                            }
                        >
                            Delete Activity
                        </AppButton>

                    </Stack>

                </FormSection>

            </PageCard>

            {/* ACTIVITY */}

            <PageCard>

                <FormSection
                    title="Activity Information"
                >

                    <InfoRow
                        label="Activity Code"
                        value={activity.activityCode}
                    />

                    <InfoRow
                        label="Activity Name"
                        value={activity.name}
                    />

                    {canReadTors && (

                        <InfoRow
                            label="Terms of Reference"
                            value={
                                tors.length
                                    ? (
                                        <Stack spacing={0.5}>
                                            {tors.map(tor => (
                                                <Link
                                                    key={tor._id}
                                                    component="button"
                                                    underline="hover"
                                                    onClick={() =>
                                                        navigate(`/tors/${tor._id}`)
                                                    }
                                                    sx={{
                                                        fontWeight: 600,
                                                        textAlign: "left"
                                                    }}>
                                                    {tor.torNumber} – {tor.title} ({tor.status})
                                                </Link>
                                            ))}
                                        </Stack>
                                    )
                                    : "No TOR linked"
                            }
                        />

                    )}

                    <InfoRow
                        label="Project"
                        value={
                            formatCodeName(
                                activity.project,
                                "projectCode"
                            )
                        }
                    />

                    <InfoRow
                        label="Program"
                        value={
                            formatCodeName(
                                activity.program,
                                "programCode"
                            )
                        }
                    />

                    <InfoRow
                        label="Activity Type"
                        value={activity.activityType}
                    />

                    <InfoRow
                        label="Participant Source"
                        value={activity.participantSource}
                    />

                    <InfoRow
                        label="Target Groups"
                        value={
                            targetGroups.length
                                ? (
                                    <Stack sx={{ flexWrap: "wrap" }}
                                        direction="row"
                                        spacing={1}
                                        useFlexGap
                                    >
                                        {targetGroups.map(group => (
                                            <Chip
                                                key={group}
                                                label={group}
                                                size="small"
                                            />
                                        ))}
                                    </Stack>
                                )
                                : "-"
                        }
                    />

                    <InfoRow
                        label="Facilitator"
                        value={activity.facilitator}
                    />

                    <InfoRow
                        label="Target Participants"
                        value={activity.targetParticipants ?? "-"}
                    />

                    <InfoRow
                        label="Description"
                        value={activity.description}
                    />

                </FormSection>

            </PageCard>

            {/* DATE AND LOCATION */}

            <PageCard>

                <FormSection
                    title="Date and Location"
                >

                    <InfoRow
                        label="Activity Date"
                        value={
                            formatDate(
                                activity.activityDate
                            )
                        }
                    />

                    <InfoRow
                        label="Region"
                        value={activity.region}
                    />

                    <InfoRow
                        label={zoneLabel}
                        value={activity.zone}
                    />

                    <InfoRow
                        label="Woreda"
                        value={activity.woreda}
                    />

                    <InfoRow
                        label="Venue / Site"
                        value={activity.location}
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
                                status={activity.status}
                            />
                        }
                    />

                    <InfoRow
                        label="Remarks"
                        value={activity.remarks}
                    />

                    <InfoRow
                        label="Created At"
                        value={
                            formatDateTime(
                                activity.createdAt
                            )
                        }
                    />

                    <InfoRow
                        label="Updated At"
                        value={
                            formatDateTime(
                                activity.updatedAt
                            )
                        }
                    />

                </FormSection>

            </PageCard>

            {backButton}

            <ConfirmDeleteDialog
                open={openDelete}
                title="Delete Activity"
                message="Are you sure you want to delete this activity?"
                onClose={() =>
                    setOpenDelete(false)
                }
                onConfirm={handleDelete}
            />

        </PageContainer>
    );

};


export default ActivityDetailsPage;
