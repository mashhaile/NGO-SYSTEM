import {
    useNavigate
}
from "react-router-dom";


import {
    useDispatch,
    useSelector
}
from "react-redux";


import {

PageContainer,

PageHeader,

PageCard

}
from "../../../components/ui";


import {
    ArrowBack
}
from "@mui/icons-material";


import ActivityRunForm
from "../components/ActivityRunForm";


import {
    createActivityRunThunk
}
from "../store";






const ActivityRunCreatePage = ()=>{


const navigate = useNavigate();


const dispatch = useDispatch();





const {
    loading
}
=
useSelector(
state=>state.activityRuns
);







const handleSubmit = async (data) => {

    console.log("DATA FROM FORM", data);

    try {

        await dispatch(createActivityRunThunk(data)).unwrap();

        navigate("/activity-runs");

    } catch (error) {

        console.error(error);

    }

};









return (

<PageContainer>




<PageHeader


title="Create Activity Run"


subtitle="Create a new implementation of an activity"


action={()=>navigate("/activity-runs")}


actionLabel="Back"


actionIcon={<ArrowBack/>}


/>






<PageCard>


<ActivityRunForm


onSubmit={handleSubmit}


loading={loading}


/>


</PageCard>







</PageContainer>


);


};





export default ActivityRunCreatePage;