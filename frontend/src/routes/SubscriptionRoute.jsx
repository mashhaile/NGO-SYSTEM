import { Navigate } from "react-router-dom";


const SubscriptionRoute = ({
    children
})=>{


const user =
JSON.parse(
localStorage.getItem("user")
);



const status =
user?.subscription?.status;



if(
    status === "expired" ||
    status === "suspended"
){

    return (

        <Navigate
            to="/subscription"
            replace
        />

    );

}



return children;


};



export default SubscriptionRoute;