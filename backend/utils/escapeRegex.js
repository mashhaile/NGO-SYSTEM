// Escapes user text so it is matched literally inside a
// RegExp / Mongo $regex (a search for "(" or ".*" must not
// break the query or become a pattern).

const escapeRegex = (value = "") =>
    String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");


module.exports = escapeRegex;
