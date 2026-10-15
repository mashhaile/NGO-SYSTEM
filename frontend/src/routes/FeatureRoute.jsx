import { Navigate } from "react-router-dom";


const FeatureRoute = ({
    children,
    feature
})=>{


const user =
    JSON.parse(
        localStorage.getItem("user")
    );



const features =
    user?.subscription?.features || {};



if(
    !features[feature]
){

    return (

        <Navigate
            to="/feature-required"
            replace
        />

    );

}



return children;


};



export default FeatureRoute;