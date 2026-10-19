import {
    useEffect,
    useState
} from "react";


import {
    useLocation,
    useNavigate,
    useParams
} from "react-router-dom";


import {
    Alert
} from "@mui/material";


import {
    ArrowBack
} from "@mui/icons-material";


import {
    PageContainer,
    PageHeader,
    LoadingState,
    ErrorState
} from "../../../components/ui";


import TorForm
    from "../components/TorForm";


import {
    getTorByIdApi,
    updateTorApi,
    submitTorApi,
    getApiErrorMessage
} from "../api/torApi";


import {
    EDITABLE_STATUSES
} from "../utils/torPermissions";



// =====================================================
// TOR EDIT PAGE
// =====================================================

const TorEditPage = () => {

    const {
        id
    } = useParams();

    const navigate =
        useNavigate();

    const location =
        useLocation();

    const [tor, setTor] =
        useState(null);

    const [loadError, setLoadError] =
        useState("");

    const [saving, setSaving] =
        useState(false);

    const [error, setError] =
        useState(
            location.state?.message || ""
        );


    useEffect(() => {

        let cancelled = false;

        getTorByIdApi(id)

            .then(data => {
                if (!cancelled) {
                    setTor(data);
                }
            })

            .catch(fetchError => {
                if (!cancelled) {
                    setLoadError(
                        getApiErrorMessage(
                            fetchError,
                            "Failed to load the TOR."
                        )
                    );
                }
            });

        return () => {
            cancelled = true;
        };

    }, [id]);


    const handleSubmit = async (data, { submit }) => {

        setSaving(true);

        setError("");

        try {

            await updateTorApi(id, data);

            if (submit) {
                await submitTorApi(id);
            }

            navigate(`/tors/${id}`);

        }
        catch (saveError) {

            setError(
                getApiErrorMessage(
                    saveError,
                    "Failed to save the TOR."
                )
            );

            window.scrollTo({
                top: 0,
                behavior: "smooth"
            });

        }
        finally {

            setSaving(false);

        }

    };


    const header = (

        <PageHeader
            title="Edit Terms of Reference"
            subtitle={
                tor?.torNumber ||
                "Update the TOR."
            }
            action={() =>
                navigate(
                    tor ? `/tors/${id}` : "/tors"
                )
            }
            actionLabel="Back"
            actionIcon={
                <ArrowBack />
            }
        />

    );


    if (loadError) {

        return (

            <PageContainer>
                {header}
                <ErrorState message={loadError} />
            </PageContainer>

        );

    }


    if (!tor) {

        return (

            <PageContainer>
                {header}
                <LoadingState message="Loading TOR..." />
            </PageContainer>

        );

    }


    if (!EDITABLE_STATUSES.includes(tor.status)) {

        return (

            <PageContainer>

                {header}

                <Alert severity="info">
                    This TOR is {tor.status.toLowerCase()} and can no longer be edited.
                </Alert>

            </PageContainer>

        );

    }


    return (

        <PageContainer>

            {header}

            {tor.status === "Returned" && tor.reviewComment && (

                <Alert
                    severity="warning"
                    sx={{ mb: 3 }}
                >
                    <strong>Returned for revision:</strong> {tor.reviewComment}
                </Alert>

            )}

            <TorForm
                key={tor._id}
                initialData={tor}
                onSubmit={handleSubmit}
                saving={saving}
                error={error}
            />

        </PageContainer>

    );

};


export default TorEditPage;
