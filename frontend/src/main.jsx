import React from "react";
import ReactDOM from "react-dom/client";

import AppRoutes from "./routes/AppRoutes";

import AppProviders from "./app/providers";

import "./index.css";


ReactDOM.createRoot(
document.getElementById("root")
)
.render(

<React.StrictMode>

<AppProviders>

<AppRoutes />

</AppProviders>

</React.StrictMode>

);