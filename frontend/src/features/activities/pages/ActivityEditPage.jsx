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
    Box,
    Card,
    CardContent,
    Typography,
    Button,
    Stack
} from "@mui/material";


import {
    ArrowBack
} from "@mui/icons-material";


import ActivityForm
from "../components/ActivityForm";


import {
    updateActivityThunk
}
from "../store";


import {
    getActivityByIdService
}
from "../services/activityService";







const ActivityEditPage = ()=>{


const {
    id
}
=
useParams();



const navigate = useNavigate();



const dispatch = useDispatch();




const {
    loading
}
=
useSelector(
    state=>state.activities
);





const [activity,setActivity] = useState(null);


const [error,setError] = useState("");








useEffect(()=>{

    loadActivity();

},[id]);









const loadActivity = async()=>{


try{


const response = await getActivityByIdService(id);



const data =

    response.data?.data

    ||

    response.data

    ||

    response;



setActivity(data);



}
catch(error){


console.error(error);


setError(

    error.response?.data?.message

    ||

    error.message

);


}



};









const handleSubmit = async(data)=>{


try{


await dispatch(

    updateActivityThunk({

        id,

        data

    })

).unwrap();



navigate("/activities");



}
catch(error){


console.error(

    "Update activity error:",

    error

);


}



};









if(error)

return (

<Typography color="error">

{error}

</Typography>

);








if(!activity)

return (

<Typography>

Loading...

</Typography>

);









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

Edit Activity

</Typography>



<Typography

color="text.secondary"

>

Update activity information

</Typography>


</Box>







<Button

variant="outlined"

startIcon={<ArrowBack/>}

onClick={()=>navigate("/activities")}

>

Back

</Button>





</Stack>









<Card>


<CardContent>


<ActivityForm


initialData={activity}


onSubmit={handleSubmit}


loading={loading}


/>



</CardContent>


</Card>








</Box>

);


};




export default ActivityEditPage;