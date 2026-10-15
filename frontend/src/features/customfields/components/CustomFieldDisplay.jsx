import {

Box,

Typography,

Paper,

Divider

}

from "@mui/material";




const CustomFieldDisplay = ({

fields=[]

})=>{



if(!fields.length){


return (

<Typography

color="text.secondary"

>

No custom information available

</Typography>

);


}




return (

<Box>


{

fields.map(item=>(


<Paper

key={item._id}

sx={{

p:2,

mb:2,

borderRadius:2

}}

variant="outlined"

>


<Box

sx={{

display:"flex",

justifyContent:"space-between",

alignItems:"center"

}}

>


<Typography

fontWeight="600"

>

{

item.fieldId?.label || "Field"

}

</Typography>





<Typography

color="text.secondary"

>

{

item.value || "-"

}

</Typography>



</Box>


</Paper>


))


}



</Box>

);


};



export default CustomFieldDisplay;