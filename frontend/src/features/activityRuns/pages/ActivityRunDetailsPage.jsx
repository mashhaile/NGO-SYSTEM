import {
    useEffect,
    useState
}
from "react";


import {
    useParams,
    useNavigate
}
from "react-router-dom";


import {
    useDispatch
}
from "react-redux";


import {

PageContainer,

PageHeader,

PageCard

}
from "../../../components/ui";


import {
    ArrowBack,
    Edit
}
from "@mui/icons-material";


import {
    Button,
    Stack,
    Typography,
    Grid,
    Divider
}
from "@mui/material";


import {
    getActivityRunByIdThunk
}
from "../store";






const ActivityRunDetailsPage = ()=>{


const {
    id
}
=
useParams();


const navigate = useNavigate();


const dispatch = useDispatch();



const [run,setRun]=useState(null);







useEffect(()=>{


load();


},[id]);







const load=async()=>{


try{


const data = await dispatch(

getActivityRunByIdThunk(id)

).unwrap();



setRun(data);



}
catch(error){


console.error(error);


}


};









if(!run){


return null;


}









return (

<PageContainer>





<PageHeader

title="Activity Run Details"

subtitle={run.runCode}


/>









<PageCard>


<Stack

direction="row"

spacing={2}

mb={3}

>


<Button

variant="outlined"

startIcon={<ArrowBack/>}

onClick={()=>navigate("/activity-runs")}

>

Back

</Button>





<Button

variant="contained"

startIcon={<Edit/>}

onClick={()=>navigate(

`/activity-runs/${id}/edit`

)}

>

Edit

</Button>



</Stack>









<Grid

container

spacing={3}

>



<Grid size={{xs:12,md:6}}>


<Typography variant="subtitle2">

Run Code

</Typography>


<Typography>

{run.runCode}

</Typography>


</Grid>








<Grid size={{xs:12,md:6}}>


<Typography variant="subtitle2">

Activity

</Typography>


<Typography>

{run.activity?.name || "-"}

</Typography>


</Grid>








<Grid size={{xs:12,md:6}}>


<Typography variant="subtitle2">

Start Date

</Typography>


<Typography>

{

new Date(run.startDate)
.toLocaleDateString()

}

</Typography>


</Grid>








<Grid size={{xs:12,md:6}}>


<Typography variant="subtitle2">

End Date

</Typography>


<Typography>

{

new Date(run.endDate)
.toLocaleDateString()

}

</Typography>


</Grid>








<Grid size={{xs:12,md:6}}>


<Typography variant="subtitle2">

Location

</Typography>


<Typography>

{run.location || "-"}

</Typography>


</Grid>








<Grid size={{xs:12,md:6}}>


<Typography variant="subtitle2">

Status

</Typography>


<Typography>

{run.status}

</Typography>


</Grid>








<Grid size={12}>


<Divider/>

</Grid>








<Grid size={12}>


<Typography variant="subtitle2">

Notes

</Typography>


<Typography>

{run.notes || "-"}

</Typography>


</Grid>






</Grid>





</PageCard>






</PageContainer>


);


};





export default ActivityRunDetailsPage;