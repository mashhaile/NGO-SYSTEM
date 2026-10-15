export const selectAuth = (state)=>state.auth;


export const selectUser = (state)=>state.auth.user;


export const selectIsAuthenticated = (state)=>
    state.auth.isAuthenticated;


export const selectAuthInitialized = (state)=>
    state.auth.initialized;


export const selectAuthLoading = (state)=>
    state.auth.loading;