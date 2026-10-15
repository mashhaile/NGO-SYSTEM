import axiosClient from "../../../services/axiosClient";


export const getEnrollmentsApi = async(params)=>{


const response = await axiosClient.get(

    "/enrollments",

    {
        params
    }

);


return response.data;


};