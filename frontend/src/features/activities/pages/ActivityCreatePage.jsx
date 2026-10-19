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


import ActivityForm
    from "../components/ActivityForm";


import {
    createActivityThunk
} from "../store";



// =====================================================
// ACTIVITY CREATE PAGE
// =====================================================

const ActivityCreatePage = () => {

    const navigate =
        useNavigate();

    const dispatch =
        useDispatch();

    const {
        loading
    } = useSelector(
        state => state.activities
    );


    const handleSubmit = async (data) => {

        try {

            await dispatch(
                createActivityThunk(data)
            ).unwrap();

            navigate("/activities");

        }
        catch (error) {

            console.error(
                "Create activity error:",
                error
            );

        }

    };


    return (

        <PageContainer>

            <PageHeader
                title="Create Activity"
                subtitle="Add a new program activity."
                action={() =>
                    navigate("/activities")
                }
                actionLabel="Back"
                actionIcon={
                    <ArrowBack />
                }
            />

            <ActivityForm
                onSubmit={handleSubmit}
                loading={loading}
            />

        </PageContainer>

    );

};


export default ActivityCreatePage;
