import {
    useNavigate
} from "react-router-dom";

import {
    useDispatch,
    useSelector
} from "react-redux";

import {
    ArrowBack
} from "@mui/icons-material";

import {
    PageContainer,
    PageHeader,
    PageCard,
    AppAlert
} from "../../../components/ui";

import ProgramForm
    from "../components/ProgramForm";

import {
    createProgramThunk,
    getProgramsThunk
} from "../store";


const ProgramCreatePage = () => {

    const navigate = useNavigate();

    const dispatch = useDispatch();


    const {
        loading,
        error
    } = useSelector(
        state => state.programs
    );


    // ==========================================
    // CREATE PROGRAM
    // ==========================================

    const save = async (data) => {

        try {

            const result = await dispatch(
                createProgramThunk(data)
            );


            // ==================================
            // SUCCESS
            // ==================================

            if (
                createProgramThunk.fulfilled.match(
                    result
                )
            ) {

                // Refresh program list

                await dispatch(
                    getProgramsThunk({
                        search: "",
                        page: 1,
                        limit: 10
                    })
                );


                // Go back to program list

                navigate(
                    "/programs",
                    {
                        replace: true
                    }
                );


                return;

            }


            // ==================================
            // FAILED
            // ==================================

            console.error(
                "PROGRAM CREATE FAILED:",
                result.payload ||
                result.error
            );

        } catch (error) {

            console.error(
                "PROGRAM CREATE ERROR:",
                error
            );

        }

    };


    // ==========================================
    // RENDER
    // ==========================================

    return (

        <PageContainer>


            {/* =====================================
                HEADER
            ===================================== */}

            <PageHeader

                title="Create Program"

                subtitle="Add a new NGO program"

                action={() =>
                    navigate("/programs")
                }

                actionLabel="Back"

                actionIcon={
                    <ArrowBack />
                }

            />


            {/* =====================================
                FORM
            ===================================== */}

            <PageCard>


                {error && (

                    <AppAlert
                        severity="error"
                        message={
                            typeof error === "string"
                                ? error
                                : "Failed to create program."
                        }
                    />

                )}


                <ProgramForm

                    onSubmit={save}

                    loading={loading}

                />


            </PageCard>


        </PageContainer>

    );

};


export default ProgramCreatePage;