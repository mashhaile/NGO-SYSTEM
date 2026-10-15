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
    Box,
    Card,
    CardContent,
    Typography,
    Button,
    Stack
}
from "@mui/material";


import {
    ArrowBack
}
from "@mui/icons-material";


import ActivityForm
from "../components/ActivityForm";


import {
    createActivityThunk
}
from "../store";





const ActivityCreatePage = ()=>{


const navigate = useNavigate();

const dispatch = useDispatch();



const {

    loading

}
=
useSelector(

state=>state.activities

);





const handleSubmit=async(data)=>{


try{


await dispatch(

    createActivityThunk(data)

).unwrap();



navigate("/activities");



}

catch(error){


console.error(

"Create activity error:",

error

);


}



};






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

Create Activity

</Typography>



<Typography

color="text.secondary"

>

Add new program activity

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


onSubmit={handleSubmit}


loading={loading}


/>


</CardContent>


</Card>






</Box>

);


};



export default ActivityCreatePage;