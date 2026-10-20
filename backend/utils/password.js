const crypto = require("crypto");
const bcrypt = require("bcrypt");

const ApiError = require("./apiError");


// =====================================================
// PASSWORD RULES
// =====================================================
//
// One place for every password the system sets:
// user creation, organization registration, change
// password and admin reset.
//
// =====================================================

const PASSWORD_MIN_LENGTH = 8;

const PASSWORD_RULE_TEXT =
    `At least ${PASSWORD_MIN_LENGTH} characters, with at least one letter and one number.`;

const BCRYPT_ROUNDS = 10;


// Returns a reason string, or null when the password is acceptable.

const getPasswordProblem = (password, { email } = {}) => {

    const value =
        typeof password === "string"
            ? password
            : "";

    if (value.length < PASSWORD_MIN_LENGTH) {
        return `Password must be at least ${PASSWORD_MIN_LENGTH} characters.`;
    }

    if (value.length > 128) {
        return "Password must be at most 128 characters.";
    }

    if (!/[A-Za-z]/.test(value) || !/[0-9]/.test(value)) {
        return "Password must contain at least one letter and one number.";
    }

    if (
        email &&
        value.toLowerCase() === String(email).toLowerCase()
    ) {
        return "Password must not be the same as the email address.";
    }

    return null;

};


const assertStrongPassword = (password, context) => {

    const problem =
        getPasswordProblem(password, context);

    if (problem) {
        throw new ApiError(
            problem,
            400,
            [
                {
                    field: "password",
                    message: problem
                }
            ]
        );
    }

};


const hashPassword = (password) =>
    bcrypt.hash(password, BCRYPT_ROUNDS);


// Temporary password for admin resets: 12 characters,
// letters and digits only (easy to read out or type).

const generateTemporaryPassword = () => {

    const letters = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz";
    const digits = "23456789";
    const all = letters + digits;

    const pick = (set) =>
        set[crypto.randomInt(set.length)];

    const chars = [
        pick(letters),
        pick(digits),
        ...Array.from({ length: 10 }, () => pick(all))
    ];

    // shuffle so the letter/digit are not always first

    for (let i = chars.length - 1; i > 0; i--) {
        const j = crypto.randomInt(i + 1);
        [chars[i], chars[j]] = [chars[j], chars[i]];
    }

    return chars.join("");

};


module.exports = {
    PASSWORD_MIN_LENGTH,
    PASSWORD_RULE_TEXT,
    getPasswordProblem,
    assertStrongPassword,
    hashPassword,
    generateTemporaryPassword
};
