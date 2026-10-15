import {
    useEffect,
    useState
} from "react";


import {
    useNavigate
} from "react-router-dom";


import {
    Box,
    CircularProgress
} from "@mui/material";


import {
    ArrowBack
} from "@mui/icons-material";


import {
    PageContainer,
    PageHeader,
    PageCard,
    AppAlert
} from "../../../components/ui";


import {
    getDonorsService
} from "../../donors/services/donorService";


import {
    getProgramsLookupService
} from "../../programs/services/lookupService";


import {
    getProjectLookupService
} from "../../projects/services/lookupService";


import {
    getActivityLookupService
} from "../../activities/services/lookupService";


import {
    getActivityRunLookupService
} from "../../activityRuns/services/lookupService";


import {
    useCreateDonation
} from "../hooks/useDonations";


import DonationForm
    from "../components/DonationForm";



// ==========================================
// NORMALIZE LOOKUP RESPONSE
// ==========================================

const extractArray = (
    response
) => {

    if (Array.isArray(response)) {

        return response;

    }


    if (
        Array.isArray(
            response?.data
        )
    ) {

        return response.data;

    }


    if (
        Array.isArray(
            response?.data?.data
        )
    ) {

        return response.data.data;

    }


    if (
        Array.isArray(
            response?.data?.items
        )
    ) {

        return response.data.items;

    }


    if (
        Array.isArray(
            response?.items
        )
    ) {

        return response.items;

    }


    if (
        Array.isArray(
            response?.organizations
        )
    ) {

        return response.organizations;

    }


    return [];

};



const DonationCreatePage = () => {

    const navigate =
        useNavigate();


    // ==========================================
    // LOOKUP DATA
    // ==========================================

    const [
        donors,
        setDonors
    ] = useState([]);


    const [
        programs,
        setPrograms
    ] = useState([]);


    const [
        projects,
        setProjects
    ] = useState([]);


    const [
        activities,
        setActivities
    ] = useState([]);


    const [
        activityRuns,
        setActivityRuns
    ] = useState([]);


    const [
        loading,
        setLoading
    ] = useState(true);


    const [
        loadError,
        setLoadError
    ] = useState(null);


    const createDonation =
        useCreateDonation();



    // ==========================================
    // LOAD LOOKUPS
    // ==========================================

    useEffect(() => {

        const loadLookups = async () => {

            try {

                setLoading(true);

                setLoadError(null);


                const [

                    donorResponse,

                    programResponse,

                    projectResponse,

                    activityResponse,

                    activityRunResponse

                ] = await Promise.all([

                    getDonorsService(),

                    getProgramsLookupService(),

                    getProjectLookupService(),

                    getActivityLookupService(),

                    getActivityRunLookupService()

                ]);


                // ======================================
                // NORMALIZE ALL LOOKUPS
                // ======================================

                const donorList =
                    extractArray(
                        donorResponse
                    );


                const programList =
                    extractArray(
                        programResponse
                    );


                const projectList =
                    extractArray(
                        projectResponse
                    );


                const activityList =
                    extractArray(
                        activityResponse
                    );


                const activityRunList =
                    extractArray(
                        activityRunResponse
                    );


                console.log(
                    "Donation lookup data:",
                    {
                        donors: donorList,
                        programs: programList,
                        projects: projectList,
                        activities: activityList,
                        activityRuns: activityRunList
                    }
                );


                // ======================================
                // SET LOOKUPS
                // ======================================

                setDonors(
                    donorList
                );


                setPrograms(
                    programList
                );


                setProjects(
                    projectList
                );


                setActivities(
                    activityList
                );


                setActivityRuns(
                    activityRunList
                );

            }

            catch (error) {

                console.error(
                    "Failed to load donation lookups:",
                    error
                );


                setLoadError(

                    error
                        ?.response
                        ?.data
                        ?.message ||

                    error?.message ||

                    "Failed to load donation lookups"

                );

            }

            finally {

                setLoading(false);

            }

        };


        loadLookups();

    }, []);



    // ==========================================
    // SUBMIT
    // ==========================================

    const handleSubmit = async (
        data
    ) => {

        try {

            await createDonation.mutateAsync(
                data
            );


            navigate(
                "/donations"
            );

        }

        catch (error) {

            console.error(
                "Failed to create donation:",
                error
            );

        }

    };



    // ==========================================
    // LOADING
    // ==========================================

    if (loading) {

        return (

            <PageContainer>

                <PageHeader

                    title="Create Donation"

                    subtitle="Add a new donation"

                    action={() =>
                        navigate("/donations")
                    }

                    actionLabel="Back"

                    actionIcon={
                        <ArrowBack />
                    }

                />


                <PageCard>

                    <Box
                        sx={{
                            display: "flex",
                            justifyContent: "center",
                            alignItems: "center",
                            minHeight: 300
                        }}
                    >

                        <CircularProgress />

                    </Box>

                </PageCard>

            </PageContainer>

        );

    }



    // ==========================================
    // RENDER
    // ==========================================

    return (

        <PageContainer>

            <PageHeader

                title="Create Donation"

                subtitle="Add a new donation"

                action={() =>
                    navigate("/donations")
                }

                actionLabel="Back"

                actionIcon={
                    <ArrowBack />
                }

            />


            <PageCard>

                {loadError && (

                    <AppAlert
                        severity="error"
                        message={loadError}
                    />

                )}


                {createDonation.error && (

                    <AppAlert
                        severity="error"
                        message={

                            createDonation
                                .error
                                ?.response
                                ?.data
                                ?.message ||

                            createDonation
                                .error
                                ?.message ||

                            "Failed to create donation"

                        }
                    />

                )}


                <DonationForm

                    donors={
                        donors
                    }

                    programs={
                        programs
                    }

                    projects={
                        projects
                    }

                    activities={
                        activities
                    }

                    activityRuns={
                        activityRuns
                    }

                    onSubmit={
                        handleSubmit
                    }

                    loading={
                        createDonation.isPending
                    }

                />

            </PageCard>

        </PageContainer>

    );

};


export default DonationCreatePage;