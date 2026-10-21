// Unit tests for the security helpers. No database needed.
// Run: npm test   (or: node --test tests/)

const test = require("node:test");
const assert = require("node:assert/strict");

const {
    getPasswordProblem,
    generateTemporaryPassword
} = require("../utils/password");

const escapeRegex = require("../utils/escapeRegex");

const {
    getErrorStatus,
    getErrorMessage
} = require("../utils/errorStatus");

const ApiError = require("../utils/apiError");


// =====================================================
// PASSWORD RULES
// =====================================================

test("password: too short is rejected", () => {
    assert.match(getPasswordProblem("abc12"), /at least 8/);
});

test("password: needs a letter and a number", () => {
    assert.match(getPasswordProblem("abcdefgh"), /letter and one number/);
    assert.match(getPasswordProblem("12345678"), /letter and one number/);
});

test("password: must not equal the email", () => {
    assert.match(
        getPasswordProblem("Admin123@x.org", { email: "admin123@x.org" }),
        /same as the email/
    );
});

test("password: a good password passes", () => {
    assert.equal(getPasswordProblem("Field2026visit"), null);
});

test("temporary password: 12 chars, letters + digits, passes the rule", () => {
    for (let i = 0; i < 200; i++) {
        const value = generateTemporaryPassword();
        assert.equal(value.length, 12);
        assert.match(value, /^[A-Za-z0-9]+$/);
        // no look-alike characters
        assert.doesNotMatch(value, /[0O1lI]/);
        assert.equal(getPasswordProblem(value), null);
    }
});


// =====================================================
// SEARCH ESCAPING
// =====================================================

test("escapeRegex: special characters are matched literally", () => {
    for (const text of ["(", "[x]", "a.b", "c++", "50%", "a|b", "\\"]) {
        const regex = new RegExp(escapeRegex(text), "i");
        assert.ok(regex.test(`before ${text} after`), text);
    }
});

test("escapeRegex: '.' does not act as a wildcard", () => {
    assert.equal(new RegExp(escapeRegex("a.b")).test("a-b"), false);
});


// =====================================================
// ERROR -> HTTP STATUS
// =====================================================

test("errors: explicit status wins", () => {
    assert.equal(getErrorStatus(new ApiError("Locked", 423)), 423);
});

test("errors: plain business errors are client errors, not 500", () => {
    assert.equal(getErrorStatus(new Error("Program not found")), 404);
    assert.equal(getErrorStatus(new Error("Donor email already exists")), 409);
    assert.equal(getErrorStatus(new Error("You do not have permission to do this")), 403);
    assert.equal(getErrorStatus(new Error("End date must be after start date")), 400);
});

test("errors: database errors map to 400 / 409", () => {
    const cast = Object.assign(new Error("Cast to ObjectId failed"), { name: "CastError", path: "_id" });
    assert.equal(getErrorStatus(cast), 400);
    assert.equal(getErrorMessage(cast), "Invalid ID.");

    const duplicate = Object.assign(new Error("E11000"), { code: 11000, keyValue: { email: "x" } });
    assert.equal(getErrorStatus(duplicate), 409);
    assert.match(getErrorMessage(duplicate), /email already exists/);
});

test("errors: real crashes stay 500 and are hidden in production", () => {
    const crash = new TypeError("Cannot read properties of undefined");
    assert.equal(getErrorStatus(crash), 500);

    const previous = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    try {
        assert.equal(getErrorMessage(crash), "Something went wrong. Please try again.");
    }
    finally {
        process.env.NODE_ENV = previous;
    }
});
