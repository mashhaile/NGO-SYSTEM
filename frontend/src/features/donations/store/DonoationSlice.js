import {
    createSlice,
    createAsyncThunk
}
from "@reduxjs/toolkit";


import {

    getDonorsService,

    createDonorService,

    updateDonorService,

    deleteDonorService

}
from "../services/donorService";





export const getDonorsThunk =
createAsyncThunk(

"donor/getAll",

async()=>{

    return await getDonorsService();

}

);





export const createDonorThunk =
createAsyncThunk(

"donor/create",

async(data)=>{

    return await createDonorService(data);

}

);





export const updateDonorThunk =
createAsyncThunk(

"donor/update",

async({id,data})=>{


    return await updateDonorService(
        id,
        data
    );


}

);





export const deleteDonorThunk =
createAsyncThunk(

"donor/delete",

async(id)=>{


    await deleteDonorService(id);


    return id;

}

);







const donorSlice =
createSlice({

name:"donor",


initialState:{


    donors:[],


    loading:false,


    error:null


},



reducers:{},



extraReducers:(builder)=>{


builder


.addCase(
getDonorsThunk.pending,
(state)=>{

state.loading=true;

})


.addCase(
getDonorsThunk.fulfilled,
(state,action)=>{


state.loading=false;


state.donors =
action.payload;


})



.addCase(
createDonorThunk.fulfilled,
(state,action)=>{


state.donors.unshift(
action.payload
);


})



.addCase(
deleteDonorThunk.fulfilled,
(state,action)=>{


state.donors =
state.donors.filter(
x=>x._id!==action.payload
);


});


}


});


export default donorSlice.reducer;