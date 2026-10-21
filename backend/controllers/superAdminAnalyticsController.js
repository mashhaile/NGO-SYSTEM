const {
    getErrorStatus,
    getErrorMessage
} = require("../utils/errorStatus");

const analyticsService =
require("../services/superAdminAnalyticsService");



const getPlatformAnalytics = async (

    req,

    res

)=>{


    try{


        const data =
        await analyticsService
        .getPlatformAnalytics();



        res.json({

            success:true,

            data

        });



    }


    catch(error){


        res.status(getErrorStatus(error)).json({

            success:false,

            message:getErrorMessage(error)

        });


    }


};




module.exports = {

    getPlatformAnalytics

};