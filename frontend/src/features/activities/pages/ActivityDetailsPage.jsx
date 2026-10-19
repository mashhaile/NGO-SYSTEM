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

    Box,

    Typography,

    Button,

    Chip,

    Divider,

    Stack

}
from "@mui/material";


import {

    ArrowBack,

    Edit,

    Delete

}
from "@mui/icons-material";


import {
    deleteActivityThunk
}
from "../store";


import {
    getActivityByIdService
}
from "../services/activityService";


import {

    PageContainer,

    PageHeader,

    PageCard,

    ConfirmDeleteDialog,

    LoadingState

}
from "../../../components/ui";


import useZoneLabel
from "../../locations/hooks/useZoneLabel";






const statusColors={


    Planned:"warning",

    Ongoing:"info",

    Completed:"success",

    Cancelled:"error"


};










const ActivityDetailsPage=()=>{


const {id}=useParams();


const navigate=useNavigate();


const dispatch=useDispatch();




const [activity,setActivity]=useState(null);

const [loading,setLoading]=useState(true);

const [error,setError]=useState("");

const [openDelete,setOpenDelete]=useState(false);


const zoneLabel=useZoneLabel(activity?.regionCode);










useEffect(()=>{


loadActivity();


},[id]);










const loadActivity=async()=>{


try{


setLoading(true);



const response=

await getActivityByIdService(id);



const data=

response?.data?.data ||

response?.data ||

response;



setActivity(data);



}

catch(error){


setError(

error.response?.data?.message ||

"Failed to load activity"

);


}

finally{


setLoading(false);


}



};









const handleDelete=async()=>{


await dispatch(

deleteActivityThunk(id)

).unwrap();



navigate("/activities");


};









if(loading){


return(

<PageContainer>

<PageCard>

<LoadingState

message="Loading activity..."

/>

</PageCard>

</PageContainer>

);


}










if(error){


return(

<PageContainer>

<PageCard>

<Typography color="error">

{error}

</Typography>

</PageCard>

</PageContainer>

);


}









return(

<PageContainer>





<PageHeader


title="Activity Details"


subtitle="View complete activity information"



action={()=>navigate(`/activities/${id}/edit`)}


actionLabel="Edit"


actionIcon={<Edit/>}


/>










<Stack

direction="row"

spacing={2}

mb={3}

>


<Button


variant="outlined"


startIcon={<ArrowBack/>}


onClick={()=>navigate("/activities")}

>

Back

</Button>


</Stack>









<PageCard>





<Typography

variant="h6"

fontWeight="700"

mb={2}

>

Activity Information

</Typography>





<Divider sx={{mb:3}}/>









<InfoRow

label="Activity Code"

value={activity.activityCode}

/>







<InfoRow

label="Activity Name"

value={activity.name}

/>








<InfoRow

label="Program"

value={

activity.program

?

`${activity.program.programCode} - ${activity.program.name}`

:

"-"

}

/>









<InfoRow

label="Activity Type"

value={activity.activityType}

/>









<InfoRow

label="Participant Source"

value={activity.participantSource}

/>









<Box mb={2}>


<Typography

fontWeight="600"

sx={{width:220}}

>

Target Groups

</Typography>



<Stack

direction="row"

spacing={1}

mt={1}

flexWrap="wrap"

>


{

(activity.targetGroups || [])

.map(group=>(


<Chip

key={group}

label={group}

size="small"

/>


))

}



</Stack>



</Box>









<InfoRow

label="Description"

value={activity.description}

/>









<InfoRow

label="Activity Date"

value={

activity.activityDate

?

new Date(activity.activityDate)

.toLocaleDateString()

:

"-"

}

/>









<InfoRow

label="Region"

value={activity.region}

/>



<InfoRow

label={zoneLabel}

value={activity.zone}

/>



<InfoRow

label="Woreda"

value={activity.woreda}

/>



<InfoRow

label="Venue / Site"

value={activity.location}

/>









<InfoRow

label="Facilitator"

value={activity.facilitator}

/>









<InfoRow

label="Target Participants"

value={activity.targetParticipants}

/>









<InfoRow

label="Remarks"

value={activity.remarks}

/>









<Box mt={3}>


<Typography

fontWeight="700"

mb={1}

>

Status

</Typography>



<Chip


label={activity.status}


color={

statusColors[activity.status]

||

"default"

}


/>


</Box>








</PageCard>









<Box

display="flex"

justifyContent="flex-end"

mt={3}

>


<Button


variant="contained"


color="error"


startIcon={<Delete/>}


onClick={()=>setOpenDelete(true)}

>

Delete Activity

</Button>


</Box>









<ConfirmDeleteDialog


open={openDelete}


title="Delete Activity"


message="Are you sure you want to delete this activity?"


onClose={()=>setOpenDelete(false)}


onConfirm={handleDelete}


/>






</PageContainer>


);


};









const InfoRow=({label,value})=>(


<Box

display="flex"

mb={2}

>


<Typography

fontWeight="600"

sx={{

width:220

}}

>

{label}

</Typography>




<Typography

color="text.secondary"

>

{value || "-"}

</Typography>



</Box>


);






export default ActivityDetailsPage;