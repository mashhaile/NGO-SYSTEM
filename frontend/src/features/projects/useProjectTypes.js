import { useEffect, useState } from "react";

import axiosClient from "../../services/axiosClient";


// The organization's project types (Lookups > Projects >
// Project Type): Development, Humanitarian, Emergency ...
// as [{ value: id, label }]. Empty when there are none.
const useProjectTypes = () => {

    const [types, setTypes] = useState([]);

    useEffect(() => {
        let alive = true;
        axiosClient.get("/lookups/module/Project/category/ProjectType")
            .then(response => {
                const list = Array.isArray(response.data?.data) ? response.data.data : [];
                if (alive) setTypes(list.filter(type => type.isActive !== false).map(type => ({ value: type._id, label: type.value })));
            })
            .catch(() => {
                // no types: the filter is not shown
            });
        return () => { alive = false; };
    }, []);

    return types;

};

export default useProjectTypes;
