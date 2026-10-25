// =====================================================
// NOTIFICATIONS
// =====================================================
//
// Each notification is for one user of one organization
// (the bell at the top shows the user's own). link is the
// page it is about, so the bell can open it.
//
// notifyPermission: everyone whose role allows something
// (e.g. "expense.approve": the approvers), except the person
// who did it. notifyUser: one person. Both never stop the
// action that caused them: a failure is logged and ignored.
//
// =====================================================

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

            link:
                data.link || "",

            createdBy:
                data.createdBy || null,

            referenceId:
                data.referenceId || null

        });



    return notification;

};




// ==========================================
// Notify Users (never fails the caller)
// ==========================================

const idOf = (value) =>
    value?._id || value || null;


const safely = async (work) => {
    try {
        await work();
    }
    catch (error) {
        console.error("Notification failed:", error.message);
    }
};


// one person (not the one who did it)
const notifyUser = ({ organizationId, to, byUserId = null, type = "approval", title, message, link = "" }) =>
    safely(async () => {
        const user = idOf(to);
        if (!user || String(user) === String(idOf(byUserId))) return;
        await createNotification({ organization: organizationId, user, type, title, message, link, createdBy: idOf(byUserId) });
    });


// everyone whose role allows the permission, except the
// person who did it (built-in and custom roles)
const notifyPermission = ({ organizationId, permission, byUserId = null, type = "approval", title, message, link = "" }) =>
    safely(async () => {
        const users =
            await require("./roleService").usersWithPermission(organizationId, permission);
        for (const user of users) {
            if (String(user._id) === String(idOf(byUserId))) continue;
            await createNotification({ organization: organizationId, user: user._id, type, title, message, link, createdBy: idOf(byUserId) });
        }
    });




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
        Math.min(Number(query.limit) || 20, 100);


    const skip =
        (page - 1) * limit;



    const filter = {

        organization:
            organizationId,

        user:
            userId,

        isDeleted:false,

        ...(String(query.unread) === "true" ? { isRead: false } : {})

    };



    const [
        notifications,
        total,
        unread
    ] = await Promise.all([


        Notification.find(filter)

        .sort({
            createdAt:-1
        })

        .skip(skip)

        .limit(limit),



        Notification.countDocuments(
            filter
        ),



        Notification.countDocuments({
            organization: organizationId,
            user: userId,
            isRead: false,
            isDeleted: false
        })

    ]);




    return {

        page,

        limit,

        total,

        unread,

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

        const ApiError = require("../utils/apiError");

        throw new ApiError(
            "Notification not found",
            404
        );

    }



    notification.isRead = true;

    notification.readAt =
        new Date();



    await notification.save();



    return notification;

};




// ==========================================
// Mark All As Read
// ==========================================

const markAllAsRead = async (
    userId,
    organizationId
) => {

    const result =
        await Notification.updateMany(
            { organization: organizationId, user: userId, isRead: false, isDeleted: false },
            { $set: { isRead: true, readAt: new Date() } }
        );

    return { updated: result.modifiedCount };

};




// ==========================================
// Unread Count
// ==========================================

const getUnreadCount = async (
    userId,
    organizationId
) => {


    const count =
        await Notification.countDocuments({
            ...(organizationId ? { organization: organizationId } : {}),
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

    notifyUser,

    notifyPermission,

    getUserNotifications,

    getOrganizationNotifications,

    markAsRead,

    markAllAsRead,

    getUnreadCount

};
