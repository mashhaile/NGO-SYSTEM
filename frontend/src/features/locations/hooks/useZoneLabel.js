import {
    useEffect,
    useState
} from "react";


import {
    getLocationsApi
} from "../api/locationApi";


// =====================================================
// ZONE LABEL
// =====================================================
//
// Label for the second location level of a region:
// "Sub City" for Addis Ababa, otherwise "Zone".
//
// =====================================================

const useZoneLabel = (
    regionCode
) => {

    const [regions, setRegions] =
        useState([]);

    useEffect(() => {

        let cancelled = false;

        getLocationsApi(1)

            .then(items => {
                if (!cancelled) {
                    setRegions(items);
                }
            })

            .catch(() => {});

        return () => {
            cancelled = true;
        };

    }, []);


    const region =
        regions.find(
            item =>
                item.pcode === regionCode
        );

    return (
        region?.childLabel ||
        "Zone"
    );

};


export default useZoneLabel;
