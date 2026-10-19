import {
    useCallback,
    useEffect,
    useState
}
from "react";


import {

    Box,
    Grid,
    TextField,
    MenuItem,
    Button,
    Stack

}
from "@mui/material";


import {
    Save
}
from "@mui/icons-material";


import {
    getActivityLookupService
}
from "../../activities/services/lookupService";


import LocationCascadeFields
from "../../locations/components/LocationCascadeFields";




const initialState = {

    activity:null,

    name:"",

    startDate:"",

    endDate:"",

    region:"",
    regionCode:"",
    zone:"",
    zoneCode:"",
    woreda:"",
    woredaCode:"",

    location:"",

    status:"Planned",

    notes:""

};





const ActivityRunForm = ({

    initialData = {},

    onSubmit,

    loading = false

})=>{


const [formData,setFormData] = useState(initialState);


const [activities,setActivities] = useState([]);





useEffect(()=>{

    loadActivities();

},[]);






useEffect(()=>{


if(initialData && Object.keys(initialData).length){


setFormData({

    activity:
        initialData.activity || null,

    name:
        initialData.name || "",


    startDate:
        initialData.startDate
        ?
        new Date(initialData.startDate)
        .toISOString()
        .substring(0,10)
        :
        "",


    endDate:
        initialData.endDate
        ?
        new Date(initialData.endDate)
        .toISOString()
        .substring(0,10)
        :
        "",


    region:
        initialData.region || "",

    regionCode:
        initialData.regionCode || "",

    zone:
        initialData.zone || "",

    zoneCode:
        initialData.zoneCode || "",

    woreda:
        initialData.woreda || "",

    woredaCode:
        initialData.woredaCode || "",


    location:
        initialData.location || "",


    status:
        initialData.status || "Planned",


    notes:
        initialData.notes || ""

});


}


},[initialData]);







const loadActivities = async()=>{

try{


const response = await getActivityLookupService();


setActivities(

response.data.data || []

);


}
catch(error){

console.error(
"Activity lookup error",
error
);

}


};








const change=(field,value)=>{


setFormData(prev=>({

...prev,

[field]:value

}));


};



// location cascade: several fields at once

const changeFields=useCallback((patch)=>{

setFormData(prev=>({

...prev,

...patch

}));

},[]);









const submit=(e)=>{


e.preventDefault();



// prevent empty date

if(!formData.startDate){

alert("Start date is required");

return;

}



const payload = {


activity:
formData.activity?._id || null,


name:
formData.name.trim(),


startDate:
formData.startDate,


endDate:
formData.endDate || null,


region:
formData.region,

regionCode:
formData.regionCode,

zone:
formData.zone,

zoneCode:
formData.zoneCode,

woreda:
formData.woreda,

woredaCode:
formData.woredaCode,


location:
formData.location || null,


status:
formData.status,


notes:
formData.notes || null


};




console.log(
"ACTIVITY RUN PAYLOAD",
payload
);



onSubmit(payload);



};








return (

<Box

component="form"

onSubmit={submit}

>


<Grid

container

spacing={3}

>




<Grid size={12}>


<TextField

select

fullWidth

label="Activity"

value={
formData.activity?._id || ""
}

onChange={(e)=>{


const selected = activities.find(

item=>item._id === e.target.value

);


change(

"activity",

selected

);


}}

required

>


{

activities.map(item=>(


<MenuItem

key={item._id}

value={item._id}

>

{item.activityCode} - {item.name}

</MenuItem>


))


}



</TextField>


</Grid>







<Grid size={{xs:12,md:6}}>


<TextField

fullWidth

label="Run Name"

required

value={formData.name}

onChange={(e)=>

change(
"name",
e.target.value
)

}

/>


</Grid>








<Grid size={{xs:12,md:6}}>


<TextField

fullWidth

type="date"

label="Start Date"

required

InputLabelProps={{

shrink:true

}}

value={formData.startDate}

onChange={(e)=>

change(
"startDate",
e.target.value
)

}

/>


</Grid>








<Grid size={{xs:12,md:6}}>


<TextField

fullWidth

type="date"

label="End Date"

InputLabelProps={{

shrink:true

}}

value={formData.endDate}

onChange={(e)=>

change(
"endDate",
e.target.value
)

}

/>


</Grid>








<LocationCascadeFields

value={formData}

onChange={changeFields}

size="medium"

renderItem={(field,key)=>(

<Grid key={key} size={{xs:12,md:6}}>

{field}

</Grid>

)}

/>



<Grid size={{xs:12,md:6}}>


<TextField

fullWidth

label="Venue / Site"

value={formData.location}

onChange={(e)=>

change(
"location",
e.target.value
)

}

/>


</Grid>








<Grid size={{xs:12,md:6}}>


<TextField

select

fullWidth

label="Status"

value={formData.status}

onChange={(e)=>

change(
"status",
e.target.value
)

}

>


<MenuItem value="Planned">
Planned
</MenuItem>


<MenuItem value="Active">
Active
</MenuItem>


<MenuItem value="Completed">
Completed
</MenuItem>


<MenuItem value="Cancelled">
Cancelled
</MenuItem>


</TextField>


</Grid>








<Grid size={12}>


<TextField

fullWidth

multiline

rows={3}

label="Notes"

value={formData.notes}

onChange={(e)=>

change(
"notes",
e.target.value
)

}

/>


</Grid>





</Grid>







<Stack

mt={3}

direction="row"

justifyContent="flex-end"

>


<Button

type="submit"

variant="contained"

startIcon={<Save/>}

disabled={loading}

>


{

loading

?

"Saving..."

:

"Save Activity Run"

}


</Button>


</Stack>





</Box>


);


};





export default ActivityRunForm;