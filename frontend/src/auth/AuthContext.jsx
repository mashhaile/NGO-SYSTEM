import {
    createContext,
    useContext,
    useEffect,
    useState
} from "react";

import axiosClient from "../services/axiosClient";


// ==========================================
// AUTH CONTEXT
// ==========================================

const AuthContext = createContext(null);


// ==========================================
// AUTH PROVIDER
// ==========================================

export const AuthProvider = ({ children }) => {

    const [user, setUser] = useState(null);

    const [loading, setLoading] = useState(true);


    // ==========================================
    // LOAD CURRENT USER
    // ==========================================

    useEffect(() => {

        const loadCurrentUser = async () => {

            try {

                const token =
                    localStorage.getItem("token");

                if (!token) {

                    setUser(null);

                    return;

                }


                const response =
                    await axiosClient.get(
                        "/auth/me"
                    );


                setUser(
                    response.data?.data || null
                );

            }
            catch (error) {

                console.error(
                    "Failed to load current user:",
                    error
                );

                setUser(null);

            }
            finally {

                setLoading(false);

            }

        };


        loadCurrentUser();

    }, []);


    // ==========================================
    // LOGOUT
    // ==========================================

    const logout = () => {

        localStorage.removeItem("token");

        setUser(null);

        window.location.href = "/login";

    };


    // ==========================================
    // CONTEXT VALUE
    // ==========================================

    const value = {

        user,

        loading,

        logout,

        isAuthenticated:
            Boolean(user)

    };


    return (

        <AuthContext.Provider value={value}>

            {children}

        </AuthContext.Provider>

    );

};


// ==========================================
// AUTH HOOK
// ==========================================

export const useAuth = () => {

    const context =
        useContext(AuthContext);


    if (!context) {

        throw new Error(
            "useAuth must be used inside AuthProvider"
        );

    }


    return context;

};