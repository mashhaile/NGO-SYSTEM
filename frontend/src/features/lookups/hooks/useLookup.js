import {
    useEffect,
    useState
} from "react";

import {
    getLookupByCategoryService
} from "../services/lookupService";


// ==========================================================
// LOOKUP OPTIONS HOOK
// ==========================================================

const useLookup = (
    module,
    category
) => {

    const [
        data,
        setData
    ] = useState([]);

    const [
        loading,
        setLoading
    ] = useState(false);

    const [
        error,
        setError
    ] = useState(null);


    useEffect(() => {

        if (!module || !category) {

            setData([]);

            return;

        }


        let mounted = true;


        const load = async () => {

            try {

                setLoading(true);

                setError(null);


                const response =
                    await getLookupByCategoryService(
                        module,
                        category
                    );


                if (!mounted) {
                    return;
                }


                const responseData =
                    response?.data ||
                    response ||
                    [];


                setData(
                    Array.isArray(responseData)
                        ? responseData
                        : []
                );

            }

            catch (error) {

                if (!mounted) {
                    return;
                }


                console.error(
                    "Lookup loading error:",
                    error
                );


                setError(
                    error?.response?.data?.message ||
                    error?.message ||
                    "Failed to load lookup options."
                );


                setData([]);

            }

            finally {

                if (mounted) {

                    setLoading(false);

                }

            }

        };


        load();


        return () => {

            mounted = false;

        };

    }, [
        module,
        category
    ]);


    return {

        data,

        loading,

        error

    };

};


export default useLookup;