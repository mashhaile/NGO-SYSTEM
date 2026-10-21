// Readable message from an API error (message, then field errors).
export const getApiErrorMessage = (error, fallback) => {

    const data = error?.response?.data;

    const details =
        Array.isArray(data?.errors)
            ? data.errors.map(item => item?.message).filter(Boolean)
            : [];

    return (
        data?.message ||
        details.join(" ") ||
        error?.message ||
        fallback
    );

};
