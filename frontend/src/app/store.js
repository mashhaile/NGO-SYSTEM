import {
    configureStore
} from "@reduxjs/toolkit";

import {
    setReduxStore
} from "../services/axiosClient";


// ==========================================================
// AUTH
// ==========================================================

import authReducer
    from "../features/auth/store/authSlice";


// ==========================================================
// SUPER ADMIN — ORGANIZATION CONTEXT
// ==========================================================

import organizationContextReducer
    from "../features/superadmin/store/organizationContextSlice";


// ==========================================================
// DASHBOARD
// ==========================================================

import {
    dashboardReducer
} from "../features/dashboard";


// ==========================================================
// BENEFICIARIES
// ==========================================================

import {
    beneficiaryReducer
} from "../features/beneficiaries";


// ==========================================================
// ENTERPRISES
// ==========================================================

import enterpriseReducer
    from "../features/enterprise/store/enterpriseSlice";

import enterpriseMemberReducer
    from "../features/enterprise/store/enterpriseMemberSlice";


// ==========================================================
// CUSTOM FIELDS
// ==========================================================

import {
    customFieldReducer
} from "../features/customfields/store";


// ==========================================================
// PROGRAMS
// ==========================================================

import {
    programReducer
} from "../features/programs";


// ==========================================================
// PROJECTS
// ==========================================================

import projectReducer
    from "../features/projects/store";


// ==========================================================
// ENROLLMENTS
// ==========================================================

import {
    enrollmentReducer
} from "../features/enrollments";


// ==========================================================
// ACTIVITIES
// ==========================================================

import {
    activityReducer
} from "../features/activities";


// ==========================================================
// ATTENDANCE
// ==========================================================

import {
    attendanceReducer
} from "../features/attendance/store";


// ==========================================================
// ACTIVITY RUNS
// ==========================================================

import activityRunReducer
    from "../features/activityRuns/store";


// ==========================================================
// SERVICE DELIVERY
// ==========================================================

import {
    serviceDeliveryReducer
} from "../features/ServiceDelivery/store";


// ==========================================================
// DONATIONS
// ==========================================================

import {
    donationReducer
} from "../features/donations/store";


// ==========================================================
// SUPER ADMIN — ORGANIZATIONS
// ==========================================================

import organizationReducer
    from "../features/superadmin/store/organizationSlice";


// ==========================================================
// SUPER ADMIN — ANALYTICS
// ==========================================================

import superAdminAnalyticsReducer
    from "../features/superadmin/store/superAdminAnalyticsSlice";


// ==========================================================
// STORE
// ==========================================================

const store = configureStore({

    reducer: {

        // --------------------------------------------------
        // AUTHENTICATION
        // --------------------------------------------------

        auth:
            authReducer,


        // --------------------------------------------------
        // DASHBOARD
        // --------------------------------------------------

        dashboard:
            dashboardReducer,


        // --------------------------------------------------
        // BENEFICIARIES
        // --------------------------------------------------

        beneficiaries:
            beneficiaryReducer,


        // --------------------------------------------------
        // ENTERPRISES
        // --------------------------------------------------

        enterprises:
            enterpriseReducer,


        // --------------------------------------------------
        // ENTERPRISE MEMBERS
        // --------------------------------------------------

        enterpriseMembers:
            enterpriseMemberReducer,


        // --------------------------------------------------
        // CUSTOM FIELDS
        // --------------------------------------------------

        customFields:
            customFieldReducer,


        // --------------------------------------------------
        // PROGRAMS
        // --------------------------------------------------

        programs:
            programReducer,


        // --------------------------------------------------
        // PROJECTS
        // --------------------------------------------------

        projects:
            projectReducer,


        // --------------------------------------------------
        // ENROLLMENTS
        // --------------------------------------------------

        enrollments:
            enrollmentReducer,


        // --------------------------------------------------
        // ACTIVITIES
        // --------------------------------------------------

        activities:
            activityReducer,


        // --------------------------------------------------
        // ATTENDANCE
        // --------------------------------------------------

        attendance:
            attendanceReducer,


        // --------------------------------------------------
        // ACTIVITY RUNS
        // --------------------------------------------------

        activityRuns:
            activityRunReducer,


        // --------------------------------------------------
        // SERVICE DELIVERY
        // --------------------------------------------------

        serviceDelivery:
            serviceDeliveryReducer,


        // --------------------------------------------------
        // DONATIONS
        // --------------------------------------------------

        donations:
            donationReducer,


        // --------------------------------------------------
        // SUPER ADMIN — ORGANIZATIONS
        // --------------------------------------------------

        superadminOrganizations:
            organizationReducer,


        // --------------------------------------------------
        // SUPER ADMIN — ORGANIZATION CONTEXT
        // --------------------------------------------------

        organizationContext:
            organizationContextReducer,


        // --------------------------------------------------
        // SUPER ADMIN — ANALYTICS
        // --------------------------------------------------

        superAdminAnalytics:
            superAdminAnalyticsReducer

    }

});


// ==========================================================
// CONNECT REDUX STORE TO AXIOS
// ==========================================================

setReduxStore(
    store
);


// ==========================================================
// EXPORT
// ==========================================================

export {
    store
};

export default store;