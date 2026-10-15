const Organization = require("../models/Organization");
const User = require("../models/User");
const Subscription = require("../models/Subscription");
const Plan = require("../models/Plan");



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


        res.status(500).json({

            success:false,

            message:error.message

        });


    }

};



module.exports = {

    getAdminDashboard

};