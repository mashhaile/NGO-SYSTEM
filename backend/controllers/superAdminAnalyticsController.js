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


        res.status(500).json({

            success:false,

            message:error.message

        });


    }


};




module.exports = {

    getPlatformAnalytics

};