import axiosClient from "../../../services/axiosClient";


export const updateEnrollmentApi = async(

    id,

    data

)=>{


const response = await axiosClient.put(

    `/enrollments/${id}`,

    data

);


return response.data;


};