import {
    useEffect,
    useState
} from "react";

import {
    useNavigate,
    useParams
} from "react-router-dom";

import {
    useDispatch,
    useSelector
} from "react-redux";

import {
    Alert
} from "@mui/material";

import {
    ArrowBack
} from "@mui/icons-material";

import EnrollmentForm
    from "../components/EnrollmentForm";

import {
    getEnrollmentByIdThunk,
    updateEnrollmentThunk
} from "../store";

import {
    PageContainer,
    PageHeader,
    PageCard,
    LoadingState
} from "../../../components/ui";


// ==========================================
// ENROLLMENT EDIT PAGE
// ==========================================

const EnrollmentEditPage = () => {

    const { id } = useParams();

    const navigate = useNavigate();

    const dispatch = useDispatch();

    const {
        current,
        loading
    } = useSelector(
        state => state.enrollments
    );

    const [saveError, setSaveError] =
        useState("");


    useEffect(() => {

        dispatch(
            getEnrollmentByIdThunk(id)
        );

    }, [dispatch, id]);


    const enrollment =
        current && String(current._id) === String(id)
            ? current
            : null;


    const handleSubmit = async (data) => {

        setSaveError("");

        try {

            await dispatch(
                updateEnrollmentThunk({
                    id,
                    data
                })
            ).unwrap();

            navigate(`/enrollments/${id}`);

        }
        catch (error) {

            setSaveError(
                typeof error === "string"
                    ? error
                    : error?.message || "Failed to save the enrollment."
            );

        }

    };


    return (

        <PageContainer>

            <PageHeader
                title="Edit Enrollment"
                subtitle="Update the program, dates or status"
                action={() =>
                    navigate(`/enrollments/${id}`)
                }
                actionLabel="Back"
                actionIcon={<ArrowBack />}
            />

            {saveError && (
                <Alert severity="error" sx={{ mb: 3 }}>
                    {saveError}
                </Alert>
            )}

            <PageCard>

                {enrollment
                    ? (
                        <EnrollmentForm
                            initialData={enrollment}
                            onSubmit={handleSubmit}
                            loading={loading}
                        />
                    )
                    : (
                        <LoadingState message="Loading enrollment..." />
                    )}

            </PageCard>

        </PageContainer>

    );

};


export default EnrollmentEditPage;
