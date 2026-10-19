import axiosClient
    from "../../../services/axiosClient";


// =====================================================
// GET LOCATIONS
// =====================================================
//
// level 1 = Region
// level 2 = Zone   (parent = region pcode)
// level 3 = Woreda (parent = zone pcode)
//
// Results are cached for the session because the
// admin boundaries rarely change.
//
// =====================================================

const cache =
    new Map();


export const getLocationsApi =
    (
        level,
        parent = ""
    ) => {

        const key =
            `${level}|${parent}`;

        if (!cache.has(key)) {

            const request =
                axiosClient

                    .get(
                        "/locations",
                        {
                            params: {
                                level,
                                ...(parent
                                    ? { parent }
                                    : {})
                            }
                        }
                    )

                    .then(
                        response =>
                            response.data?.data || []
                    )

                    .catch(error => {

                        cache.delete(key);

                        throw error;

                    });

            cache.set(
                key,
                request
            );

        }

        return cache.get(key);

    };
