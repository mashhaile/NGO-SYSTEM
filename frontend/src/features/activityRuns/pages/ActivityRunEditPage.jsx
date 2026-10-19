import {
    useEffect,
    useState
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
    ArrowBack
} from "@mui/icons-material";


import {
    PageContainer,
    PageHeader,
    LoadingState,
    ErrorState
} from "../../../components/ui";


import ActivityRunForm
    from "../components/ActivityRunForm";


import {
    getActivityRunByIdThunk,
    updateActivityRunThunk
} from "../store";



// =====================================================
// ACTIVITY RUN EDIT PAGE
// =====================================================

const ActivityRunEditPage = () => {

    const {
        id
    } = useParams();

    const navigate =
        useNavigate();

    const dispatch =
        useDispatch();

    const {
        current,
        loading
    } = useSelector(
        state => state.activityRuns
    );


    const [loadError, setLoadError] =
        useState("");


    useEffect(() => {

        dispatch(
            getActivityRunByIdThunk(id)
        )
            .unwrap()
            .catch(error =>
                setLoadError(
                    error?.message ||
                    (typeof error === "string" ? error : "") ||
                    "Could not load activity run."
                )
            );

    }, [dispatch, id]);


    // The store may still hold a previously viewed run.

    const run =
        current?._id === id
            ? current
            : null;


    const handleSubmit = async (data) => {

        try {

            await dispatch(
                updateActivityRunThunk({
                    id,
                    data
                })
            ).unwrap();

            navigate("/activity-runs");

        }
        catch (error) {

            console.error(
                "Update activity run error:",
                error
            );

        }

    };


    return (

        <PageContainer>

            <PageHeader
                title="Edit Activity Run"
                subtitle="Update activity run information."
                action={() =>
                    navigate("/activity-runs")
                }
                actionLabel="Back"
                actionIcon={
                    <ArrowBack />
                }
            />

            {
                loadError && !run
                    ? (
                        <ErrorState
                            message={loadError}
                        />
                    )
                    : !run
                    ? (
                        <LoadingState
                            message="Loading activity run..."
                        />
                    )
                    : (
                        <ActivityRunForm
                            key={run._id}
                            initialData={run}
                            onSubmit={handleSubmit}
                            loading={loading}
                        />
                    )
            }

        </PageContainer>

    );

};


export default ActivityRunEditPage;
