import {
    Stack
} from "@mui/material";

import AppButton from "./AppButton";

const FormActions = ({
    onCancel,
    onSubmit,
    cancelLabel = "Cancel",
    submitLabel = "Save",
    submitLoading = false,
    submitLoadingText = "Saving...",
    submitDisabled = false,
    cancelDisabled = false,
    align = "right",
    children,
    sx = {}
}) => {
    return (
        <Stack
            direction={{
                xs: "column-reverse",
                sm: "row"
            }}
            spacing={1}
            sx={[{ justifyContent: align === "left"
                    ? "flex-start"
                    : align === "center"
                    ? "center"
                    : "flex-end" }, ...(Array.isArray(sx) ? sx : [sx])]}
        >
            {children}

            {onCancel && (
                <AppButton
                    variant="outlined"
                    color="inherit"
                    onClick={onCancel}
                    disabled={
                        cancelDisabled ||
                        submitLoading
                    }
                >
                    {cancelLabel}
                </AppButton>
            )}

            {onSubmit && (
                <AppButton
                    type="submit"
                    onClick={onSubmit}
                    loading={submitLoading}
                    loadingText={submitLoadingText}
                    disabled={submitDisabled}
                >
                    {submitLabel}
                </AppButton>
            )}
        </Stack>
    );
};

export default FormActions;