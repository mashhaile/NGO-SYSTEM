import { useEffect, useSyncExternalStore } from "react";
import { useSelector } from "react-redux";

import axiosClient from "../services/axiosClient";


// =====================================================
// THE ORGANIZATION'S OWN WORDS
// =====================================================
//
// An organization admin may rename the main terms
// ("Donation" -> "Fund", "Organization Admin" ->
// "Administrator") in Settings > Wording. The shared
// components (page titles, sections, labels, buttons, table
// headers, menu) pass their text through term(), so every
// screen uses the organization's words. Data (names typed
// by users) is never changed.
//
// Same rules as backend/config/terminology.js.
//
// =====================================================

const escape = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const casedLike = (match, word) =>
    match === match.toUpperCase() && /[A-Z]/.test(match) && match.length > 1 ? word.toUpperCase()
        : match === match.toLowerCase() ? word.toLowerCase()
            : word;

// terms: [{ key, singular, plural, own: { singular, plural } | null }]
export const makeReplacer = (terms = []) => {

    const pairs = [];
    for (const term of terms) {
        if (!term?.own) continue;
        const singular = String(term.own.singular || "").trim();
        const plural = String(term.own.plural || "").trim() || singular;
        if (plural && plural !== term.plural) pairs.push([term.plural, plural]);
        if (singular && singular !== term.singular) pairs.push([term.singular, singular]);
    }
    if (!pairs.length) return (text) => text;

    // one pass, longer phrases first: each piece of text is replaced once
    pairs.sort((a, b) => b[0].length - a[0].length);
    const target = new Map(pairs.map(([from, to]) => [from.toLowerCase(), to]));
    const pattern = new RegExp(`(?<![A-Za-z])(?:${pairs.map(([from]) => escape(from)).join("|")})(?![A-Za-z])`, "gi");

    return (text) => {
        if (typeof text !== "string" || !text) return text;
        return text.replace(pattern, (match) => casedLike(match, target.get(match.toLowerCase()) || match));
    };

};


// ---------------------------------------------------------------- the store

let state = { terms: [], replace: (text) => text };
const listeners = new Set();

const publish = (terms) => {
    state = { terms, replace: makeReplacer(terms) };
    listeners.forEach(listener => listener());
};

export const setTerms = (terms) => publish(Array.isArray(terms) ? terms : []);

export const loadTerms = async () => {
    try {
        setTerms((await axiosClient.get("/terminology")).data.data);
    }
    catch {
        // the default words stay
    }
};

const subscribe = (listener) => {
    listeners.add(listener);
    return () => listeners.delete(listener);
};

// term("Donations") -> "Funds" (outside React too)
export const term = (text) => state.replace(text);

// in a component: re-renders when the words change
export const useTerm = () =>
    useSyncExternalStore(subscribe, () => state.replace);

export const useTerms = () =>
    useSyncExternalStore(subscribe, () => state.terms);


// Loads the words once someone is signed in (and drops them on sign-out)
export const TermsLoader = () => {
    const userId = useSelector(current => current.auth?.user?.id || current.auth?.user?._id || null);
    useEffect(() => {
        if (userId) loadTerms();
        else setTerms([]);
    }, [userId]);
    return null;
};
