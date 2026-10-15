import {
    getNotificationsApi,
    getUnreadCountApi,
    markNotificationReadApi,
    markAllNotificationsReadApi
}
from "../api/notificationApi";



export const loadNotificationsService =
async(params)=>{

    return await getNotificationsApi(params);

};



export const loadUnreadCountService =
async()=>{

    return await getUnreadCountApi();

};



export const readNotificationService =
async(id)=>{

    return await markNotificationReadApi(id);

};



export const readAllNotificationsService =
async()=>{

    return await markAllNotificationsReadApi();

};