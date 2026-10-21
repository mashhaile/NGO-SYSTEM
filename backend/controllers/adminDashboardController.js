const {
    getErrorStatus,
    getErrorMessage
} = require("../utils/errorStatus");

const Organization = require("../models/organization");
const User = require("../models/user");
const Subscription = require("../models/subscription");
const Plan = require("../models/plan");



const getAdminDashboard = async (
    req,
    res
)=>{

    try {


        const [

            organizations,

            users,

            subscriptions,

            plans

        ] = await Promise.all([


            Organization.countDocuments(),


            User.countDocuments(),


            Subscription.countDocuments(),


            Plan.countDocuments()


        ]);



        const activeOrganizations =
            await Organization.countDocuments({

                status:"Active"

            });



        const activeSubscriptions =
            await Subscription.countDocuments({

                status:"active"

            });



        res.json({

            success:true,

            data:{


                organizations:{


                    total:
                    organizations,


                    active:
                    activeOrganizations


                },


                users:{

                    total:
                    users

                },


                subscriptions:{


                    total:
                    subscriptions,


                    active:
                    activeSubscriptions


                },


                plans:{


                    total:
                    plans

                }


            }


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

    getAdminDashboard

};