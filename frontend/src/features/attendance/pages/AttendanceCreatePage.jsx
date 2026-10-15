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


import AttendanceForm
from "../components/AttendanceForm";


import {
createAttendanceThunk
}
from "../store";





const AttendanceCreatePage=()=>{


const navigate=useNavigate();


const dispatch=useDispatch();



const {
loading
}
=
useSelector(
state=>state.attendance
);







const handleSubmit=async(data)=>{


try{


await dispatch(

createAttendanceThunk(data)

).unwrap();



navigate("/attendance");


}
catch(error){

console.error(error);

}


};






return (

<PageContainer>


<PageHeader

title="Create Attendance"

subtitle="Create attendance session for activity"

action={()=>navigate("/attendance")}

actionLabel="Back"

actionIcon={<ArrowBack/>}

/>





<PageCard>


<AttendanceForm

onSubmit={handleSubmit}

loading={loading}

/>


</PageCard>




</PageContainer>

);


};


export default AttendanceCreatePage;