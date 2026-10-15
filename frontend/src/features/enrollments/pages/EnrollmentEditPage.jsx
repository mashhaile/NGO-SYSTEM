import {
    useEffect
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

    Box,

    Card,

    CardContent,

    Typography,

    Stack,

    Button

} from "@mui/material";



import {
    ArrowBack
} from "@mui/icons-material";



import EnrollmentForm
from "../components/EnrollmentForm";



import {

    getEnrollmentByIdThunk,

    updateEnrollmentThunk

} from "../store";









const EnrollmentEditPage = ()=>{



const {

    id

}=useParams();



const navigate = useNavigate();


const dispatch = useDispatch();









const {

    current,

    loading

}

=

useSelector(

    state=>state.enrollments

);









useEffect(()=>{


dispatch(

    getEnrollmentByIdThunk(id)

);



},[dispatch,id]);









const handleSubmit = async(data)=>{


try{


await dispatch(

    updateEnrollmentThunk({

        id,

        data

    })

).unwrap();





navigate("/enrollments");



}

catch(error){


console.error(

"Update enrollment error:",

error

);



}



};









if(!current){


return (

<Typography>

Loading...

</Typography>

);


}









return (



<Box>






<Stack

direction="row"

justifyContent="space-between"

alignItems="center"

mb={3}

>




<Typography

variant="h4"

fontWeight="700"

>

Edit Enrollment

</Typography>






<Button

variant="outlined"

startIcon={<ArrowBack/>}

onClick={()=>navigate("/enrollments")}

>

Back

</Button>





</Stack>









<Card>



<CardContent>



<EnrollmentForm


initialData={current}


onSubmit={handleSubmit}


loading={loading}


/>





</CardContent>



</Card>









</Box>



);



};






export default EnrollmentEditPage;