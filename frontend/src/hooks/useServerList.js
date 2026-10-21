import {
    useEffect,
    useState
} from "react";

import { getApiErrorMessage } from "../utils/apiError";


// =====================================================
// SERVER-PAGED LIST
// =====================================================
// Loads one page of a list API (debounced) whenever the
// filters or the page change. `fetchPage(params)` must
// resolve to { data, pagination: { total } } (an axios
// response is unwrapped).
//
//   const list = useServerList(getDonorsApi, { search, status });
//   <DataTable rows={list.rows} rowCount={list.total} ... />

const useServerList = (fetchPage, filters, errorMessage = "Failed to load the list.") => {

    const [paginationModel, setPaginationModel] =
        useState({ page: 0, pageSize: 10 });

    // Bumped by reload() (after a delete, ...)
    const [reloadKey, setReloadKey] = useState(0);

    const [result, setResult] =
        useState({ rows: [], total: 0, loading: true, error: "" });

    // Effect dependency: changes only when a filter value changes
    const filterKey = JSON.stringify(filters);


    useEffect(() => {

        let cancelled = false;

        const timer =
            setTimeout(() => {

                const params = {};
                Object.entries(JSON.parse(filterKey)).forEach(([key, value]) => {
                    const clean = typeof value === "string" ? value.trim() : value;
                    if (clean !== "" && clean !== null && clean !== undefined) params[key] = clean;
                });

                fetchPage({
                    ...params,
                    page: paginationModel.page + 1,
                    limit: paginationModel.pageSize
                })
                    .then(response => {
                        const body = response?.data?.pagination || Array.isArray(response?.data?.data) ? response.data : response;
                        if (!cancelled) {
                            setResult({
                                rows: body?.data || [],
                                total: body?.pagination?.total ?? body?.pagination?.totalRecords ?? 0,
                                loading: false,
                                error: ""
                            });
                        }
                    })
                    .catch(error => {
                        if (!cancelled) {
                            setResult(prev => ({
                                ...prev,
                                loading: false,
                                error: getApiErrorMessage(error, errorMessage)
                            }));
                        }
                    });

            }, 300);

        return () => {
            cancelled = true;
            clearTimeout(timer);
        };

    }, [fetchPage, filterKey, paginationModel, reloadKey, errorMessage]);


    return {
        ...result,
        paginationModel,
        setPaginationModel,
        resetPage: () => setPaginationModel(prev => ({ ...prev, page: 0 })),
        reload: () => setReloadKey(key => key + 1),
        setError: (error) => setResult(prev => ({ ...prev, error }))
    };

};


export default useServerList;
