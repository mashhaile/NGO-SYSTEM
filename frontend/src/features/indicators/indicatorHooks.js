import { useEffect, useState } from "react";

import { getMeSettingsApi } from "./api/indicatorApi";
import { DEFAULT_LIMITS } from "./utils/indicatorUtils";


// The organization's limits (on track from / at risk from).
// The defaults until loaded, or when they cannot be read.
export const useMeLimits = () => {

    const [limits, setLimits] = useState(DEFAULT_LIMITS);

    useEffect(() => {
        let alive = true;
        getMeSettingsApi()
            .then(settings => {
                if (alive && settings) setLimits({ onTrack: settings.onTrack, atRisk: settings.atRisk });
            })
            .catch(() => {
                // the defaults stay
            });
        return () => { alive = false; };
    }, []);

    return [limits, setLimits];

};
