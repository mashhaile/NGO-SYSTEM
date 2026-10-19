import {
    useState
} from "react";


import {
    useNavigate
} from "react-router-dom";


import {
    ArrowBack
} from "@mui/icons-material";


import {
    PageContainer,
    PageHeader
} from "../../../components/ui";


import TorForm
    from "../components/TorForm";


import {
    createTorApi,
    submitTorApi,
    getApiErrorMessage
} from "../api/torApi";



// =====================================================
// TOR CREATE PAGE
// =====================================================

const TorCreatePage = () => {

    const navigate =
        useNavigate();

    const [saving, setSaving] =
        useState(false);

    const [error, setError] =
        useState("");


    const handleSubmit = async (data, { submit }) => {

        setSaving(true);

        setError("");

        let created = null;

        try {

            created =
                await createTorApi(data);

            if (submit) {
                await submitTorApi(created._id);
            }

            navigate(`/tors/${created._id}`);

        }
        catch (saveError) {

            // Saved as draft but submission was refused
            // (e.g. missing sections): open it so the
            // user can see what is missing.

            if (created?._id) {

                navigate(
                    `/tors/${created._id}/edit`,
                    {
                        state: {
                            message: getApiErrorMessage(
                                saveError,
                                "Saved as draft, but it could not be submitted."
                            )
                        }
                    }
                );

                return;

            }

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


    return (

        <PageContainer>

            <PageHeader
                title="New Terms of Reference"
                subtitle="Prepare a TOR for an activity or training."
                action={() =>
                    navigate("/tors")
                }
                actionLabel="Back"
                actionIcon={
                    <ArrowBack />
                }
            />

            <TorForm
                onSubmit={handleSubmit}
                saving={saving}
                error={error}
            />

        </PageContainer>

    );

};


export default TorCreatePage;
