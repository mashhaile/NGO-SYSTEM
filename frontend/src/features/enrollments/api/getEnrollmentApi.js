import axiosClient from "../../../services/axiosClient";


export const getEnrollmentApi = async(id)=>{


const response = await axiosClient.get(

    `/enrollments/${id}`

);


return response.data;


};