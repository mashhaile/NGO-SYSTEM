import {
    configureStore
} from "@reduxjs/toolkit";


// =====================================================
// AUTH
// =====================================================

import authReducer
    from "../features/auth/store/authSlice";


// =====================================================
// SUPER ADMIN - PLANS
// =====================================================

import planReducer
    from "../features/superadmin/store/planSlice";


// =====================================================
// SUPER ADMIN - ORGANIZATIONS
// =====================================================

import organizationReducer
    from "../features/superadmin/store/organizationSlice";


// =====================================================
// STORE
// =====================================================

const store = configureStore({

    reducer: {

        auth:
            authReducer,

        superadminPlans:
            planReducer,

        superadminOrganizations:
            organizationReducer

    },

    middleware: (getDefaultMiddleware) =>

        getDefaultMiddleware({

            serializableCheck: false

        })

});


// =====================================================
// EXPORT
// =====================================================

export default store;