import { Provider } from "react-redux";

import {
    QueryClientProvider
} from "@tanstack/react-query";

import {
    ReactQueryDevtools
} from "@tanstack/react-query-devtools";


import {
    ThemeProvider,
    CssBaseline
} from "@mui/material";


import {
    BrowserRouter
} from "react-router-dom";


import {
    ToastContainer
} from "react-toastify";


import "react-toastify/dist/ReactToastify.css";


import {
    store
} from "./store";


import queryClient from "./queryClient";


import theme from "../theme";


import AuthInitializer from "./AuthInitializer";



const AppProviders = ({ children }) => {


    return (

        <Provider store={store}>


            <QueryClientProvider client={queryClient}>


                <BrowserRouter>


                    <ThemeProvider theme={theme}>


                        <CssBaseline />


                        <AuthInitializer>


                            {children}


                        </AuthInitializer>



                        <ToastContainer

                            position="top-right"

                            autoClose={3000}

                            hideProgressBar={false}

                            newestOnTop

                            closeOnClick

                            pauseOnFocusLoss

                            draggable

                            pauseOnHover

                            theme="colored"

                        />


                    </ThemeProvider>


                </BrowserRouter>


                <ReactQueryDevtools

                    initialIsOpen={false}

                />


            </QueryClientProvider>


        </Provider>

    );


};


export default AppProviders;