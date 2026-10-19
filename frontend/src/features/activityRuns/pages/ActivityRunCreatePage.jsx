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
    PageHeader
} from "../../../components/ui";


import ActivityRunForm
    from "../components/ActivityRunForm";


import {
    createActivityRunThunk
} from "../store";



// =====================================================
// ACTIVITY RUN CREATE PAGE
// =====================================================

const ActivityRunCreatePage = () => {

    const navigate =
        useNavigate();

    const dispatch =
        useDispatch();

    const {
        loading
    } = useSelector(
        state => state.activityRuns
    );


    const handleSubmit = async (data) => {

        try {

            await dispatch(
                createActivityRunThunk(data)
            ).unwrap();

            navigate("/activity-runs");

        }
        catch (error) {

            console.error(
                "Create activity run error:",
                error
            );

        }

    };


    return (

        <PageContainer>

            <PageHeader
                title="Create Activity Run"
                subtitle="Create a new implementation of an activity."
                action={() =>
                    navigate("/activity-runs")
                }
                actionLabel="Back"
                actionIcon={
                    <ArrowBack />
                }
            />

            <ActivityRunForm
                onSubmit={handleSubmit}
                loading={loading}
            />

        </PageContainer>

    );

};


export default ActivityRunCreatePage;
