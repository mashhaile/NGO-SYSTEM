import {
    useEffect
} from "react";

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


import ProjectForm
    from "../components/projectForm";


import {
    createProjectThunk
} from "../store";


// =====================================================
// PROJECT CREATE PAGE
// =====================================================

const ProjectCreatePage = () => {

    const navigate = useNavigate();

    const dispatch = useDispatch();


    // =====================================================
    // REDUX
    // =====================================================

    const {
        loading,
        error
    } = useSelector(
        (state) => state.projects
    );

    // the error shows above the form: bring it into view
    useEffect(() => {
        if (error) window.scrollTo({ top: 0, behavior: "smooth" });
    }, [error]);


    // =====================================================
    // SAVE PROJECT
    // =====================================================

    const handleSubmit = async (data) => {

        try {

            const result = await dispatch(
                createProjectThunk(data)
            );


            if (
                createProjectThunk.fulfilled.match(
                    result
                )
            ) {

                navigate(
                    "/projects"
                );

            }

        }
        catch (error) {

            console.error(
                "CREATE PROJECT ERROR:",
                error
            );

        }

    };


    // =====================================================
    // RENDER
    // =====================================================

    return (

        <PageContainer>


            {/* =================================================
                HEADER
            ================================================= */}

            <PageHeader

                title="Create Project"

                subtitle="Add a new NGO project"

                action={() =>
                    navigate(
                        "/projects"
                    )
                }

                actionLabel="Back"

                actionIcon={
                    <ArrowBack />
                }

            />


            {/* =================================================
                FORM
            ================================================= */}

            <PageCard>

                {error && (

                    <AppAlert
                        severity="error"
                        message={error}
                    />

                )}


                <ProjectForm

                    onSubmit={
                        handleSubmit
                    }

                    loading={
                        loading
                    }

                />

            </PageCard>


        </PageContainer>

    );

};


export default ProjectCreatePage;