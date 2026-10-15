const Notification =
require("../models/Notification");




// ==========================================
// Create Notification
// ==========================================

const createNotification = async (
    data
) => {


    const notification =
        await Notification.create({

            organization:
                data.organization,

            user:
                data.user || null,

            type:
                data.type || "system",

            title:
                data.title,

            message:
                data.message,

            createdBy:
                data.createdBy || null

        });



    return notification;

};




// ==========================================
// Get User Notifications
// ==========================================

const getUserNotifications = async (
    userId,
    organizationId,
    query
) => {


    const page =
        Number(query.page) || 1;


    const limit =
        Number(query.limit) || 20;


    const skip =
        (page - 1) * limit;



    const filter = {

        organization:
            organizationId,

        user:
            userId,

        isDeleted:false

    };



    const [
        notifications,
        total
    ] = await Promise.all([


        Notification.find(filter)

        .sort({
            createdAt:-1
        })

        .skip(skip)

        .limit(limit),



        Notification.countDocuments(
            filter
        )

    ]);




    return {

        page,

        limit,

        total,

        pages:
        Math.ceil(
            total / limit
        ),

        notifications

    };


};




// ==========================================
// Get Organization Notifications
// ==========================================

const getOrganizationNotifications =
async (

    organizationId,

    query

) => {


    const page =
        Number(query.page) || 1;


    const limit =
        Number(query.limit) || 20;


    const skip =
        (page - 1) * limit;




    const filter = {

        organization:
            organizationId,

        isDeleted:false

    };




    const [
        notifications,
        total
    ] = await Promise.all([


        Notification.find(filter)

        .sort({
            createdAt:-1
        })

        .skip(skip)

        .limit(limit),



        Notification.countDocuments(
            filter
        )


    ]);




    return {

        page,

        limit,

        total,

        pages:
        Math.ceil(
            total / limit
        ),

        notifications

    };


};




// ==========================================
// Mark As Read
// ==========================================

const markAsRead = async (
    id,
    userId
) => {


    const notification =
        await Notification.findOne({

            _id:id,

            user:userId,

            isDeleted:false

        });



    if(!notification){

        throw new Error(
            "Notification not found"
        );

    }



    notification.isRead = true;

    notification.readAt =
        new Date();



    await notification.save();



    return notification;

};




// ==========================================
// Unread Count
// ==========================================

const getUnreadCount = async (
    userId
) => {


    const count =
        await Notification.countDocuments({

            user:userId,

            isRead:false,

            isDeleted:false

        });



    return {

        unread:
            count

    };


};




module.exports = {


    createNotification,

    getUserNotifications,

    getOrganizationNotifications,

    markAsRead,

    getUnreadCount

};