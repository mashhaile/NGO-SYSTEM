const service =
require("../services/notificationService");




// ==========================================
// Get My Notifications
// ==========================================

const getMyNotifications = async (
    req,
    res
) => {

    try {


        const data =
            await service.getUserNotifications(

                req.user.userId,

                req.user.organizationId,

                req.query

            );



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




// ==========================================
// Get Organization Notifications
// ==========================================

const getOrganizationNotifications =
async (

    req,

    res

) => {

    try {


        const data =
            await service.getOrganizationNotifications(

                req.user.organizationId,

                req.query

            );



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




// ==========================================
// Mark Notification Read
// ==========================================

const markAsRead = async (

    req,

    res

) => {

    try {


        const data =
            await service.markAsRead(

                req.params.id,

                req.user.userId

            );



        res.json({

            success:true,

            message:
            "Notification marked as read",

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




// ==========================================
// Unread Count
// ==========================================

const getUnreadCount = async (

    req,

    res

) => {

    try {


        const data =
            await service.getUnreadCount(

                req.user.userId

            );



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


    getMyNotifications,

    getOrganizationNotifications,

    markAsRead,

    getUnreadCount


};