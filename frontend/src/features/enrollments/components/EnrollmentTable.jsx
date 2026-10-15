import {

    DataGrid

} from "@mui/x-data-grid";



import {

    Box,

    IconButton,

    Chip

} from "@mui/material";



import {

    Visibility,

    Edit,

    Delete

} from "@mui/icons-material";



import {

    useNavigate

} from "react-router-dom";



import {

    useDispatch

} from "react-redux";



import {

    deleteEnrollmentThunk

} from "../store";









const EnrollmentTable = ({


    data=[],

    loading=false


})=>{





const navigate = useNavigate();


const dispatch = useDispatch();









const columns=[




{

field:"beneficiary",

headerName:"Beneficiary",

flex:1.2,


renderCell:(params)=>{


const beneficiary=params.row.beneficiary;


return beneficiary

?

`${beneficiary.firstName} ${beneficiary.lastName}`

:

"-";


}



},







{

field:"program",

headerName:"Program",

flex:1.5,


renderCell:(params)=>{


return (

params.row.program?.name || "-"

);


}



},







{

field:"enrollmentDate",

headerName:"Enrollment Date",

flex:1,


renderCell:(params)=>{


return params.row.enrollmentDate

?

new Date(

params.row.enrollmentDate

).toLocaleDateString()

:

"-";


}


},







{

field:"status",

headerName:"Status",

flex:0.8,


renderCell:(params)=>{


let color="default";


if(params.value==="Active")

color="success";


if(params.value==="Completed")

color="primary";


if(params.value==="Dropped")

color="error";



return (


<Chip

label={params.value}

color={color}

size="small"

/>


);



}



},







{

field:"actions",

headerName:"Actions",

width:160,


sortable:false,


renderCell:(params)=>{


return (


<Box>




<IconButton


color="info"


onClick={()=>navigate(

`/enrollments/${params.row._id}`

)}


>


<Visibility/>


</IconButton>







<IconButton


color="primary"


onClick={()=>navigate(

`/enrollments/${params.row._id}/edit`

)}


>


<Edit/>


</IconButton>







<IconButton


color="error"


onClick={()=>{


if(

window.confirm(

"Delete this enrollment?"

)

){


dispatch(

deleteEnrollmentThunk(

params.row._id

)

);


}



}}


>


<Delete/>


</IconButton>






</Box>



);



}



}



];









return (



<Box

sx={{

height:600,

width:"100%"

}}

>



<DataGrid



rows={data}



columns={columns}



loading={loading}



getRowId={(row)=>row._id}



pageSizeOptions={[10,25,50]}



initialState={{


pagination:{


paginationModel:{


pageSize:10,

page:0


}


}


}}


/>



</Box>



);



};





export default EnrollmentTable;