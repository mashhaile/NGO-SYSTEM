import {
    useEffect,
    useState
} from "react";


import {
    useDispatch,
    useSelector
} from "react-redux";


import {
    useNavigate,
    useParams
} from "react-router-dom";


import {
    PageContainer,
    PageHeader,
    PageCard,
    LoadingState,
    AppAlert
} from "../../../components/ui";


import {
    getDonorsService
} from "../../donors/services/DonorService";


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
    getDonationByIdThunk,
    updateDonationThunk
} from "../store/DonationThunks";


import {
    clearCurrentDonation
} from "../store/DonationSlice";


import DonationForm
    from "../components/DonationForm";



const DonationEditPage = () => {

    const {
        id
    } = useParams();


    const dispatch =
        useDispatch();


    const navigate =
        useNavigate();


    // =====================================================
    // REDUX
    // =====================================================

    const {
        currentDonation,
        detailsLoading,
        saving,
        error
    } = useSelector(
        (state) =>
            state.donations
    );


    // =====================================================
    // LOOKUP STATE
    // =====================================================

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
        lookupLoading,
        setLookupLoading
    ] = useState(true);


    const [
        lookupError,
        setLookupError
    ] = useState(null);



    // =====================================================
    // LOAD DONATION + LOOKUPS
    // =====================================================

    useEffect(() => {

        dispatch(
            clearCurrentDonation()
        );


        dispatch(
            getDonationByIdThunk(id)
        );


        const loadLookups = async () => {

            try {

                setLookupLoading(true);

                setLookupError(null);


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


                // =================================================
                // DONORS
                // =================================================

                setDonors(

                    Array.isArray(
                        donorResponse?.data
                    )

                        ? donorResponse.data

                        : Array.isArray(
                            donorResponse
                        )

                            ? donorResponse

                            : []

                );


                // =================================================
                // PROGRAMS
                // =================================================

                setPrograms(

                    Array.isArray(
                        programResponse
                    )

                        ? programResponse

                        : Array.isArray(
                            programResponse?.data?.data
                        )

                            ? programResponse.data.data

                            : Array.isArray(
                                programResponse?.data
                            )

                                ? programResponse.data

                                : []

                );


                // =================================================
                // PROJECTS
                // =================================================

                setProjects(

                    Array.isArray(
                        projectResponse
                    )

                        ? projectResponse

                        : Array.isArray(
                            projectResponse?.data?.data
                        )

                            ? projectResponse.data.data

                            : Array.isArray(
                                projectResponse?.data
                            )

                                ? projectResponse.data

                                : []

                );


                // =================================================
                // ACTIVITIES
                // =================================================

                setActivities(

                    Array.isArray(
                        activityResponse
                    )

                        ? activityResponse

                        : Array.isArray(
                            activityResponse?.data?.data
                        )

                            ? activityResponse.data.data

                            : Array.isArray(
                                activityResponse?.data
                            )

                                ? activityResponse.data

                                : []

                );


                // =================================================
                // ACTIVITY RUNS
                // =================================================

                setActivityRuns(

                    Array.isArray(
                        activityRunResponse
                    )

                        ? activityRunResponse

                        : Array.isArray(
                            activityRunResponse?.data?.data
                        )

                            ? activityRunResponse.data.data

                            : Array.isArray(
                                activityRunResponse?.data
                            )

                                ? activityRunResponse.data

                                : []

                );

            }

            catch (error) {

                console.error(
                    "Failed to load donation lookups:",
                    error
                );


                console.error(
                    "Lookup response:",
                    error?.response?.data
                );


                setLookupError(

                    error
                        ?.response
                        ?.data
                        ?.message ||

                    error?.message ||

                    "Failed to load donation lookups"

                );

            }

            finally {

                setLookupLoading(false);

            }

        };


        loadLookups();


        return () => {

            dispatch(
                clearCurrentDonation()
            );

        };

    }, [
        dispatch,
        id
    ]);



    // =====================================================
    // SUBMIT
    // =====================================================

    const handleSubmit = async (
        data
    ) => {

        const result =
            await dispatch(
                updateDonationThunk({

                    id,

                    data

                })
            );


        if (
            updateDonationThunk.fulfilled.match(
                result
            )
        ) {

            navigate(
                `/donations/${id}`
            );

        }

    };



    // =====================================================
    // LOADING
    // =====================================================

    if (
        detailsLoading ||
        lookupLoading
    ) {

        return (

            <PageContainer>

                <PageHeader
                    title="Edit Donation"
                    subtitle="Update donation information"
                />

                <PageCard>

                    <LoadingState
                        message="Loading donation..."
                    />

                </PageCard>

            </PageContainer>

        );

    }



    // =====================================================
    // NOT FOUND
    // =====================================================

    if (
        !currentDonation
    ) {

        return (

            <PageContainer>

                <PageHeader
                    title="Edit Donation"
                    subtitle="Update donation information"
                />

                <AppAlert
                    severity="error"
                    message="Donation not found."
                />

            </PageContainer>

        );

    }



    // =====================================================
    // RENDER
    // =====================================================

    return (

        <PageContainer>

            <PageHeader

                title="Edit Donation"

                subtitle={
                    currentDonation?.donationCode
                        ? `Update ${currentDonation.donationCode}`
                        : "Update donation information"
                }

            />


            {lookupError && (

                <AppAlert
                    severity="error"
                    message={
                        lookupError
                    }
                />

            )}


            {error && (

                <AppAlert
                    severity="error"
                    message={

                        error
                            ?.response
                            ?.data
                            ?.message ||

                        error?.message ||

                        String(error)

                    }
                />

            )}


            <DonationForm

                initialData={
                    currentDonation
                }

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
                    saving
                }

            />

        </PageContainer>

    );

};


export default DonationEditPage;
