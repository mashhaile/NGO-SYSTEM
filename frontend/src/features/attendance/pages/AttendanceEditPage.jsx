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
    ArrowBack
}
from "@mui/icons-material";


import AttendanceForm
from "../components/AttendanceForm";


import {

    getAttendanceByIdThunk,

    updateAttendanceThunk

}
from "../store";






const AttendanceEditPage = ()=>{


const {id}=useParams();


const navigate=useNavigate();


const dispatch=useDispatch();



const [initialData,setInitialData]=useState(null);


const [loading,setLoading]=useState(true);






useEffect(()=>{


load();


},[id]);






const load=async()=>{


try{


const data = await dispatch(

getAttendanceByIdThunk(id)

).unwrap();



setInitialData(data);



}

catch(error){

console.error(error);

}

finally{

setLoading(false);

}


};









const handleSubmit=async(data)=>{


try{


await dispatch(

updateAttendanceThunk({

id,

data

})

).unwrap();



navigate("/attendance");



}

catch(error){

console.error(error);

}


};








if(loading || !initialData){


return null;


}









return(


<PageContainer>



<PageHeader

title="Edit Attendance"

subtitle="Update attendance session information"

action={()=>navigate("/attendance")}

actionLabel="Back"

actionIcon={<ArrowBack/>}

/>






<PageCard>


<AttendanceForm


initialData={initialData}


onSubmit={handleSubmit}


loading={loading}


/>


</PageCard>





</PageContainer>


);


};



export default AttendanceEditPage;