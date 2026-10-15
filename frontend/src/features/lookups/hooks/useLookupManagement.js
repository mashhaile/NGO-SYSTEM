import { useCallback, useEffect, useState } from "react";

import {
    getLookupsService,
    getLookupByIdService,
    createLookupService,
    createLookupsBulkService,
    updateLookupService,
    deleteLookupService,
} from "../services/lookupService";

// =====================================
// LOOKUP MANAGEMENT HOOK
// =====================================

const useLookupManagement = (initialParams = {}) => {

    // =====================================
    // STATE
    // =====================================

    const [data, setData] = useState([]);

    const [loading, setLoading] = useState(false);

    const [error, setError] = useState(null);

    const [selectedLookup, setSelectedLookup] =
        useState(null);

    const [saving, setSaving] = useState(false);

    const [deleting, setDeleting] = useState(false);


    // =====================================
    // FETCH ALL LOOKUPS
    // =====================================

    const fetchLookups = useCallback(
        async (params = initialParams) => {

            try {

                setLoading(true);

                setError(null);

                const response =
                    await getLookupsService(params);

                setData(
                    Array.isArray(response?.data)
                        ? response.data
                        : []
                );

                return response;

            } catch (error) {

                console.error(
                    "Lookup management loading error:",
                    error
                );

                setError(
                    error?.response?.data?.message ||
                    error?.message ||
                    "Failed to load lookups"
                );

                setData([]);

                throw error;

            } finally {

                setLoading(false);

            }

        },
        [initialParams]
    );


    // =====================================
    // GET SINGLE LOOKUP
    // =====================================

    const getLookup = useCallback(
        async (id) => {

            try {

                setError(null);

                const response =
                    await getLookupByIdService(id);

                const lookup =
                    response?.data || null;

                setSelectedLookup(lookup);

                return lookup;

            } catch (error) {

                console.error(
                    "Lookup loading error:",
                    error
                );

                setError(
                    error?.response?.data?.message ||
                    error?.message ||
                    "Failed to load lookup"
                );

                throw error;

            }

        },
        []
    );


    // =====================================
    // CREATE SINGLE LOOKUP
    // =====================================

    const createLookup = useCallback(
        async (lookupData) => {

            try {

                setSaving(true);

                setError(null);

                const response =
                    await createLookupService(
                        lookupData
                    );

                await fetchLookups();

                return response;

            } catch (error) {

                console.error(
                    "Lookup creation error:",
                    error
                );

                setError(
                    error?.response?.data?.message ||
                    error?.message ||
                    "Failed to create lookup"
                );

                throw error;

            } finally {

                setSaving(false);

            }

        },
        [fetchLookups]
    );


    // =====================================
    // CREATE MULTIPLE LOOKUPS
    // =====================================

    const createLookupsBulk = useCallback(
        async (lookupData) => {

            try {

                setSaving(true);

                setError(null);

                /*
                 * Expected:
                 *
                 * {
                 *     category: "MaritalStatus",
                 *
                 *     values: [
                 *         {
                 *             value: "Single",
                 *             code: "SINGLE"
                 *         },
                 *         {
                 *             value: "Married",
                 *             code: "MARRIED"
                 *         }
                 *     ],
                 *
                 *     active: true
                 * }
                 */

                const response =
                    await createLookupsBulkService(
                        lookupData
                    );

                await fetchLookups();

                return response;

            } catch (error) {

                console.error(
                    "Bulk lookup creation error:",
                    error
                );

                setError(
                    error?.response?.data?.message ||
                    error?.message ||
                    "Failed to create lookups"
                );

                throw error;

            } finally {

                setSaving(false);

            }

        },
        [fetchLookups]
    );


    // =====================================
    // UPDATE LOOKUP
    // =====================================

    const updateLookup = useCallback(
        async (id, lookupData) => {

            try {

                setSaving(true);

                setError(null);

                const response =
                    await updateLookupService(
                        id,
                        lookupData
                    );

                await fetchLookups();

                if (
                    selectedLookup?._id === id
                ) {

                    await getLookup(id);

                }

                return response;

            } catch (error) {

                console.error(
                    "Lookup update error:",
                    error
                );

                setError(
                    error?.response?.data?.message ||
                    error?.message ||
                    "Failed to update lookup"
                );

                throw error;

            } finally {

                setSaving(false);

            }

        },
        [
            fetchLookups,
            getLookup,
            selectedLookup,
        ]
    );


    // =====================================
    // DELETE LOOKUP
    // =====================================

    const deleteLookup = useCallback(
        async (id) => {

            try {

                setDeleting(true);

                setError(null);

                const response =
                    await deleteLookupService(id);

                await fetchLookups();

                if (
                    selectedLookup?._id === id
                ) {

                    setSelectedLookup(null);

                }

                return response;

            } catch (error) {

                console.error(
                    "Lookup deletion error:",
                    error
                );

                setError(
                    error?.response?.data?.message ||
                    error?.message ||
                    "Failed to delete lookup"
                );

                throw error;

            } finally {

                setDeleting(false);

            }

        },
        [
            fetchLookups,
            selectedLookup,
        ]
    );


    // =====================================
    // CLEAR ERROR
    // =====================================

    const clearError = useCallback(() => {

        setError(null);

    }, []);


    // =====================================
    // CLEAR SELECTED LOOKUP
    // =====================================

    const clearSelectedLookup = useCallback(() => {

        setSelectedLookup(null);

    }, []);


    // =====================================
    // INITIAL LOAD
    // =====================================

    useEffect(() => {

        fetchLookups(initialParams);

    }, [fetchLookups, initialParams]);


    // =====================================
    // RETURN
    // =====================================

    return {

        // Data
        data,

        selectedLookup,

        // Loading
        loading,

        saving,

        deleting,

        // Error
        error,

        // Operations
        fetchLookups,

        getLookup,

        createLookup,

        createLookupsBulk,

        updateLookup,

        deleteLookup,

        // Helpers
        clearError,

        clearSelectedLookup,

    };

};

export default useLookupManagement;