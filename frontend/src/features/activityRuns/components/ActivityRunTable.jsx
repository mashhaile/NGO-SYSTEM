import {
    DataGrid
}
from "@mui/x-data-grid";


import {

Box,

IconButton,

Stack,

Tooltip,

Typography

}
from "@mui/material";


import {

Visibility,

Edit,

Delete

}
from "@mui/icons-material";


import {
useNavigate
}
from "react-router-dom";


import {
useDispatch
}
from "react-redux";


import {
deleteActivityRunThunk
}
from "../store";







const ActivityRunTable = ({

    data=[],

    loading=false

})=>{


const navigate = useNavigate();


const dispatch = useDispatch();








const handleDelete=(id)=>{


if(window.confirm(

"Delete this activity run?"

)){


dispatch(

deleteActivityRunThunk(id)

);


}


};









const columns=[




{


field:"runCode",


headerName:"Run Code",


flex:1,


minWidth:150,


renderCell:(params)=>(


<Typography

fontWeight="700"

>

{params.value}

</Typography>


)


},







{


field:"activity",


headerName:"Activity",


flex:1.5,


minWidth:220,



renderCell:(params)=>{


const activity=params.row.activity;


return activity ?


<Box>


<Typography

fontWeight="700"

>


{activity.activityCode}


</Typography>



<Typography

variant="body2"

color="text.secondary"

>


{activity.name}


</Typography>


</Box>



:

"-";


}


},







{

field:"name",

headerName:"Run Name",

flex:1.5,

minWidth:220

},







{

field:"startDate",

headerName:"Start Date",

width:140,


renderCell:(params)=>(


params.value

?

new Date(params.value)
.toLocaleDateString()

:

"-"


)


},







{

field:"endDate",

headerName:"End Date",

width:140,


renderCell:(params)=>(


params.value

?

new Date(params.value)
.toLocaleDateString()

:

"-"


)


},







{

field:"location",

headerName:"Location",

flex:1,

minWidth:150


},







{

field:"status",

headerName:"Status",

width:130


},







{

field:"actions",

headerName:"Actions",

width:160,

sortable:false,


renderCell:(params)=>(


<Stack

direction="row"

>




<Tooltip title="View">

<IconButton

color="primary"

onClick={()=>navigate(

`/activity-runs/${params.row._id}`

)}

>

<Visibility/>

</IconButton>

</Tooltip>








<Tooltip title="Edit">

<IconButton

color="secondary"

onClick={()=>navigate(

`/activity-runs/${params.row._id}/edit`

)}

>

<Edit/>

</IconButton>

</Tooltip>








<Tooltip title="Delete">

<IconButton

color="error"

onClick={()=>handleDelete(

params.row._id

)}

>

<Delete/>

</IconButton>

</Tooltip>






</Stack>


)


}




];









return (

<Box

sx={{

height:600,

background:"#fff",

borderRadius:3

}}

>


<DataGrid


rows={data}


columns={columns}


loading={loading}


getRowId={(row)=>row._id}


disableRowSelectionOnClick


pageSizeOptions={[10,25,50,100]}



/>


</Box>

);


};





export default ActivityRunTable;