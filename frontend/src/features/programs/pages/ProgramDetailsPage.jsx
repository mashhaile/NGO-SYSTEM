import {
    useEffect,
    useState
} from "react";

import {
    useNavigate,
    useParams
} from "react-router-dom";

import {
    Edit
} from "@mui/icons-material";

import {
    getProgramByIdService
} from "../services/programService";

import {
    PageContainer,
    PageHeader,
    LoadingState,
    PageCard,
    FormSection,
    InfoRow,
    AppButton,
    StatusChip
} from "../../../components/ui";

import useAuth
    from "../../auth/hooks/useAuth";

import BudgetFigureCard
    from "../../budgets/components/BudgetFigureCard";
import { formatDate, formatDateTime } from "../../../utils/date";


// =====================================================
// PROGRAM DETAILS PAGE
// =====================================================

const ProgramDetailsPage = () => {

    const {
        id
    } = useParams();

    const navigate = useNavigate();

    const { user } = useAuth();


    const [
        loading,
        setLoading
    ] = useState(true);


    const [
        program,
        setProgram
    ] = useState(null);


    // =====================================================
    // LOAD PROGRAM
    // =====================================================

    useEffect(() => {

        loadProgram();

    }, [id]);


    const loadProgram = async () => {

        try {

            setLoading(true);


            const response =
                await getProgramByIdService(id);


            /*
             * Support the common API response shapes:
             *
             * response.data
             * response.data.data
             * response.data.program
             */

            const record =
                response?.data?.data ||
                response?.data?.program ||
                response?.data ||
                null;


            setProgram(record);


        } catch (error) {

            console.error(
                "Failed loading program:",
                error
            );

            setProgram(null);

        } finally {

            setLoading(false);

        }

    };


    // =====================================================
    // FORMAT DATE
    // =====================================================


// =====================================================
    // FORMAT DATE TIME
    // =====================================================


// =====================================================
    // FORMAT NUMBER
    // =====================================================

    const formatNumber = (value) => {

        if (
            value === null ||
            value === undefined ||
            value === ""
        ) {

            return "-";

        }


        const number =
            Number(value);


        if (
            Number.isNaN(number)
        ) {

            return "-";

        }


        return number.toLocaleString();

    };


    // =====================================================
    // LOADING
    // =====================================================

    if (loading) {

        return (

            <PageContainer>

                <LoadingState
                    message="Loading program..."
                />

            </PageContainer>

        );

    }


    // =====================================================
    // NOT FOUND
    // =====================================================

    if (!program) {

        return (

            <PageContainer>

                <PageHeader
                    title="Program Details"
                    subtitle="Program record could not be found."
                />


                <PageCard>

                    <FormSection
                        title="Record Not Found"
                    >

                        <InfoRow
                            label="Program"
                            value="No program information available."
                        />

                    </FormSection>

                </PageCard>


                <AppButton
                    variant="outlined"
                    onClick={() =>
                        navigate("/programs")
                    }
                    sx={{
                        mt: 3,
                        mb: 5
                    }}
                >
                    Back to Programs
                </AppButton>

            </PageContainer>

        );

    }


    // =====================================================
    // PAGE
    // =====================================================

    return (

        <PageContainer>


            {/* =================================================
                HEADER
            ================================================= */}

            <PageHeader

                title="Program Details"

                subtitle={
                    program.programCode ||
                    program.name ||
                    "Program record"
                }

            />


            {/* =================================================
                PAGE ACTIONS
            ================================================= */}

            <PageCard>

                <FormSection>

                    <AppButton

                        variant="contained"

                        startIcon={
                            <Edit />
                        }

                        onClick={() =>
                            navigate(
                                `/programs/${id}/edit`
                            )
                        }

                    >

                        Edit Program

                    </AppButton>

                </FormSection>

            </PageCard>


            {/* =================================================
                PROGRAM INFORMATION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Program Information"
                >

                    <InfoRow
                        label="Program Code"
                        value={
                            program.programCode
                        }
                    />


                    <InfoRow
                        label="Program Name"
                        value={
                            program.name
                        }
                    />


                    <InfoRow
                        label="Category"
                        value={
                            program.category
                        }
                    />


                    <InfoRow
                        label="Description"
                        value={
                            program.description
                        }
                    />

                </FormSection>

            </PageCard>


            {/* =================================================
                PROGRAM DATES
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Program Dates"
                >

                    <InfoRow
                        label="Start Date"
                        value={
                            formatDate(
                                program.startDate
                            )
                        }
                    />


                    <InfoRow
                        label="End Date"
                        value={
                            formatDate(
                                program.endDate
                            )
                        }
                    />

                </FormSection>

            </PageCard>


            {/* =================================================
                PROGRAM TARGETS
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Program Targets"
                >

                    <InfoRow
                        label="Target Beneficiaries"
                        value={
                            formatNumber(
                                program.targetBeneficiaries
                            )
                        }
                    />

                </FormSection>

            </PageCard>


            {/* =================================================
                BUDGET (Budgets module)
            ================================================= */}

            <BudgetFigureCard
                figure={program.budget}
                level="program"
                entityId={program._id}
                user={user}
                navigate={navigate}
            />


            {/* =================================================
                RECORD INFORMATION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Record Information"
                >

                    <InfoRow

                        label="Status"

                        value={

                            <StatusChip
                                status={
                                    program.status ||
                                    "Planned"
                                }
                            />

                        }

                    />


                    <InfoRow
                        label="Created At"
                        value={
                            formatDateTime(
                                program.createdAt
                            )
                        }
                    />


                    <InfoRow
                        label="Updated At"
                        value={
                            formatDateTime(
                                program.updatedAt
                            )
                        }
                    />

                </FormSection>

            </PageCard>


            {/* =================================================
                FOOTER ACTION
            ================================================= */}

            <AppButton

                variant="outlined"

                onClick={() =>
                    navigate(
                        "/programs"
                    )
                }

                sx={{
                    mt: 3,
                    mb: 5
                }}

            >

                Back to Programs

            </AppButton>


        </PageContainer>

    );

};


export default ProgramDetailsPage;