// Same rule as the backend (backend/utils/password.js).
// The backend always checks; this only gives early feedback.

export const PASSWORD_RULE_TEXT =
    "At least 8 characters, with at least one letter and one number.";


export const getPasswordProblem = (password = "") => {

    if (password.length < 8) {
        return "Password must be at least 8 characters.";
    }

    if (!/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) {
        return "Password must contain at least one letter and one number.";
    }

    return null;

};
