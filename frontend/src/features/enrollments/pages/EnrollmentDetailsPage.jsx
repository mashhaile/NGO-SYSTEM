import {
    useEffect
} from "react";

import {
    useNavigate,
    useParams
} from "react-router-dom";

import {
    useDispatch,
    useSelector
} from "react-redux";

import {
    Stack
} from "@mui/material";

import {
    ArrowBack,
    Edit
} from "@mui/icons-material";

import {
    getEnrollmentByIdThunk
} from "../store";

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

import useAuth
    from "../../auth/hooks/useAuth";

import {
    hasPermission
} from "../../tor/utils/torPermissions";
import { formatDate } from "../../../utils/date";


// ==========================================
// ENROLLMENT DETAILS PAGE
// ==========================================

const EnrollmentDetailsPage = () => {

    const { id } = useParams();

    const navigate = useNavigate();

    const dispatch = useDispatch();

    const { user } = useAuth();

    const {
        current,
        loading,
        error
    } = useSelector(
        state => state.enrollments
    );


    useEffect(() => {

        dispatch(
            getEnrollmentByIdThunk(id)
        );

    }, [dispatch, id]);


    // The store may still hold another enrollment
    // while this one loads.

    const enrollment =
        current && String(current._id) === String(id)
            ? current
            : null;


    if (!enrollment) {

        return (

            <PageContainer>

                <PageHeader
                    title="Enrollment Details"
                    action={() => navigate("/enrollments")}
                    actionLabel="Back"
                    actionIcon={<ArrowBack />}
                />

                <PageCard>

                    {loading || !error
                        ? (
                            <LoadingState message="Loading enrollment..." />
                        )
                        : (
                            <FormSection title="Record Not Found">
                                <InfoRow
                                    label="Message"
                                    value={String(error)}
                                />
                            </FormSection>
                        )}

                </PageCard>

            </PageContainer>

        );

    }


    const beneficiary =
        enrollment.beneficiary || {};

    const program =
        enrollment.program || {};


    return (

        <PageContainer>

            <PageHeader
                title="Enrollment Details"
                subtitle={
                    [beneficiary.firstName, beneficiary.lastName]
                        .filter(Boolean)
                        .join(" ") +
                    (program.name ? ` — ${program.name}` : "")
                }
                action={() => navigate("/enrollments")}
                actionLabel="Back"
                actionIcon={<ArrowBack />}
            />


            {hasPermission(user, "enrollment.update") && (

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
                                    navigate(`/enrollments/${id}/edit`)
                                }
                            >
                                Edit Enrollment
                            </AppButton>

                        </Stack>

                    </FormSection>

                </PageCard>

            )}


            <PageCard>

                <FormSection title="Beneficiary">

                    <InfoRow
                        label="Name"
                        value={
                            [beneficiary.firstName, beneficiary.lastName]
                                .filter(Boolean)
                                .join(" ")
                        }
                    />

                    <InfoRow
                        label="Beneficiary Number"
                        value={beneficiary.beneficiaryNumber}
                    />

                </FormSection>

            </PageCard>


            <PageCard>

                <FormSection title="Project and Program">

                    <InfoRow
                        label="Project"
                        value={
                            enrollment.project
                                ? `${enrollment.project.projectCode ? `${enrollment.project.projectCode} – ` : ""}${enrollment.project.name}${enrollment.project.phaseNumber ? ` (Phase ${enrollment.project.phaseNumber})` : ""}`
                                : "Not set (an older enrollment): choose it with Edit"
                        }
                    />

                    <InfoRow
                        label="Program"
                        value={program.name}
                    />

                    <InfoRow
                        label="Program Code"
                        value={program.programCode}
                    />

                </FormSection>

            </PageCard>


            <PageCard>

                <FormSection title="Enrollment">

                    <InfoRow
                        label="Status"
                        value={
                            <StatusChip status={enrollment.status} />
                        }
                    />

                    <InfoRow
                        label="Enrollment Date"
                        value={formatDate(enrollment.enrollmentDate)}
                    />

                    <InfoRow
                        label="Completion Date"
                        value={formatDate(enrollment.completionDate)}
                    />

                    {enrollment.exitReason && (
                        <InfoRow
                            label="Exit Reason"
                            value={enrollment.exitReason}
                        />
                    )}

                    <InfoRow
                        label="Remarks"
                        value={enrollment.remarks}
                    />

                </FormSection>

            </PageCard>

        </PageContainer>

    );

};


export default EnrollmentDetailsPage;
