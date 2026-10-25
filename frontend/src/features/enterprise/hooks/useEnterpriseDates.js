import { useEffect, useState } from "react";

import { getEnterpriseByIdApi } from "../api/enterpriseApi";


// The dates of an enterprise: a membership (joined / left)
// must fall inside them, and the member forms show them.
const useEnterpriseDates = (enterpriseId) => {

    const [dates, setDates] = useState({ startDate: null, endDate: null });

    useEffect(() => {
        if (!enterpriseId) return undefined;
        let alive = true;
        getEnterpriseByIdApi(enterpriseId)
            .then(response => {
                const enterprise = response?.data || response;
                if (alive) setDates({ startDate: enterprise?.startDate || null, endDate: enterprise?.endDate || null });
            })
            .catch(() => {
                // the hint is only a help; the server still checks
            });
        return () => { alive = false; };
    }, [enterpriseId]);

    return dates;

};

export default useEnterpriseDates;
