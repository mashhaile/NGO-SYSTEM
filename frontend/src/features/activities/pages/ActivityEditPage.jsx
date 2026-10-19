import {
    useEffect,
    useState
} from "react";


import {
    useParams,
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
    LoadingState,
    ErrorState
} from "../../../components/ui";


import ActivityForm
    from "../components/ActivityForm";


import {
    updateActivityThunk
} from "../store";


import {
    getActivityByIdService
} from "../services/activityService";



// =====================================================
// ACTIVITY EDIT PAGE
// =====================================================

const ActivityEditPage = () => {

    const {
        id
    } = useParams();

    const navigate =
        useNavigate();

    const dispatch =
        useDispatch();

    const {
        loading
    } = useSelector(
        state => state.activities
    );

    const [activity, setActivity] =
        useState(null);

    const [error, setError] =
        useState("");


    // =================================================
    // LOAD
    // =================================================

    useEffect(() => {

        let cancelled = false;

        getActivityByIdService(id)

            .then(response => {

                if (!cancelled) {
                    setActivity(
                        response.data?.data ||
                        response.data ||
                        response
                    );
                }

            })

            .catch(loadError => {

                console.error(loadError);

                if (!cancelled) {
                    setError(
                        loadError.response?.data?.message ||
                        loadError.message
                    );
                }

            });

        return () => {
            cancelled = true;
        };

    }, [id]);


    // =================================================
    // SUBMIT
    // =================================================

    const handleSubmit = async (data) => {

        try {

            await dispatch(
                updateActivityThunk({
                    id,
                    data
                })
            ).unwrap();

            navigate("/activities");

        }
        catch (updateError) {

            console.error(
                "Update activity error:",
                updateError
            );

        }

    };


    const header = (

        <PageHeader
            title="Edit Activity"
            subtitle="Update activity information."
            action={() =>
                navigate("/activities")
            }
            actionLabel="Back"
            actionIcon={
                <ArrowBack />
            }
        />

    );


    if (error) {

        return (

            <PageContainer>

                {header}

                <ErrorState
                    message={error}
                />

            </PageContainer>

        );

    }


    if (!activity) {

        return (

            <PageContainer>

                {header}

                <LoadingState
                    message="Loading activity..."
                />

            </PageContainer>

        );

    }


    return (

        <PageContainer>

            {header}

            <ActivityForm
                key={activity._id}
                initialData={activity}
                onSubmit={handleSubmit}
                loading={loading}
            />

        </PageContainer>

    );

};


export default ActivityEditPage;
