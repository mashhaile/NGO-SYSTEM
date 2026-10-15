import {
    useEffect
}
from "react";


import {
    Box,
    Button,
    Stack,
    Typography
}
from "@mui/material";


import {
    Add
}
from "@mui/icons-material";


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
    getActivityRunsThunk
}
from "../store";


import ActivityRunTable
from "../components/ActivityRunTable";







const ActivityRunListPage = ()=>{


const navigate = useNavigate();


const dispatch = useDispatch();






const {

    data=[],

    loading

}
=
useSelector(
state=>state.activityRuns
);









useEffect(()=>{


dispatch(

getActivityRunsThunk({

page:1,

limit:100

})

);


},[dispatch]);









return (

<Box>





<Stack

direction="row"

justifyContent="space-between"

alignItems="center"

mb={3}

>





<Box>


<Typography

variant="h4"

fontWeight="700"

>

Activity Runs

</Typography>




<Typography

color="text.secondary"

>

Manage activity implementations and batches

</Typography>



</Box>








<Button

variant="contained"

startIcon={<Add/>}

onClick={()=>navigate(

"/activity-runs/create"

)}

>

Create Activity Run

</Button>






</Stack>










<ActivityRunTable


data={data}


loading={loading}


/>









</Box>


);


};





export default ActivityRunListPage;