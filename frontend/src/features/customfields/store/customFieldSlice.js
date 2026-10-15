import {
    createSlice
} from "@reduxjs/toolkit";


import {
    getCustomFieldsThunk
} from "./customFieldThunks";


// =====================================================
// INITIAL STATE
// =====================================================

const initialState = {

    fields: [],

    module: null,

    loading: false,

    error: null

};


// =====================================================
// SLICE
// =====================================================

const customFieldSlice = createSlice({

    name:
        "customFields",

    initialState,

    reducers: {},

    extraReducers: (builder) => {

        builder

            // =========================================
            // GET CUSTOM FIELDS
            // =========================================

            .addCase(

                getCustomFieldsThunk.pending,

                (
                    state,
                    action
                ) => {

                    state.loading =
                        true;

                    state.error =
                        null;

                    state.module =
                        action.meta.arg;

                }

            )


            .addCase(

                getCustomFieldsThunk.fulfilled,

                (
                    state,
                    action
                ) => {

                    state.loading =
                        false;

                    state.fields =
                        Array.isArray(
                            action.payload
                        )
                            ? action.payload
                            : [];

                    state.module =
                        action.meta.arg;

                }

            )


            .addCase(

                getCustomFieldsThunk.rejected,

                (
                    state,
                    action
                ) => {

                    state.loading =
                        false;

                    state.error =
                        action.payload;

                    state.fields =
                        [];

                }

            );

    }

});


export default customFieldSlice.reducer;