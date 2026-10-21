const dns = require("dns");


// =====================================================
// RESOLVE mongodb+srv:// WITH PUBLIC DNS
// =====================================================
//
// Some routers' DNS servers do not answer the SRV lookups a
// mongodb+srv:// (Atlas) address needs, so Node fails with
// "querySrv ECONNREFUSED". This turns such an address into a
// plain mongodb:// one by asking public DNS servers for the
// SRV and TXT records. Other addresses are returned as is.
//
// Used by the backup / restore scripts. The server itself
// keeps using the address directly (Render's DNS is fine).
//
// =====================================================

const PUBLIC_DNS = ["8.8.8.8", "1.1.1.1"];


const resolveMongoUri = async (uri) => {

    const match =
        String(uri || "").match(/^mongodb\+srv:\/\/([^@]+@)?([^/?]+)(\/[^?]*)?(\?.*)?$/);

    if (!match) {
        return uri;
    }

    const [, credentials = "", host, path = "/", query = ""] = match;

    const resolver = new dns.promises.Resolver();
    resolver.setServers(PUBLIC_DNS);

    const records =
        await resolver.resolveSrv(`_mongodb._tcp.${host}`);

    const hosts =
        records.map(record => `${record.name}:${record.port}`).join(",");

    // TXT holds replicaSet / authSource options
    let txtOptions = "";
    try {
        txtOptions = (await resolver.resolveTxt(host)).map(parts => parts.join("")).join("&");
    }
    catch {
        txtOptions = "";
    }

    const options =
        new URLSearchParams(txtOptions);

    for (const [key, value] of new URLSearchParams(query.replace(/^\?/, ""))) {
        options.set(key, value);
    }

    if (!options.has("tls") && !options.has("ssl")) {
        options.set("tls", "true");
    }

    return `mongodb://${credentials}${hosts}${path}?${options.toString()}`;

};


module.exports = resolveMongoUri;
