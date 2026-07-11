// WebAuthn/passkey browser ceremony helpers, shared across every TWR app.
//
// Uses the browser's native PublicKeyCredential.parseCreationOptionsFromJSON() /
// parseRequestOptionsFromJSON() / credential.toJSON() (WebAuthn Level 3) rather than hand-rolled
// base64url<->ArrayBuffer conversion — Fido2NetLib's option/response shapes are already designed
// to round-trip through exactly this JSON convention, so no translation layer is needed on either side.
window.twrAuth = {
    isPasskeySupported() {
        return typeof window.PublicKeyCredential !== "undefined";
    },

    // optionsJson: the server's CredentialCreateOptions, serialized as JSON.
    // Returns the credential's toJSON() result, serialized back to a JSON string.
    async createCredential(optionsJson) {
        const publicKey = PublicKeyCredential.parseCreationOptionsFromJSON(JSON.parse(optionsJson));
        const credential = await navigator.credentials.create({ publicKey });
        return JSON.stringify(credential.toJSON());
    },

    // optionsJson: the server's AssertionOptions, serialized as JSON.
    // Returns the assertion's toJSON() result, serialized back to a JSON string.
    async getAssertion(optionsJson) {
        const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(JSON.parse(optionsJson));
        const credential = await navigator.credentials.get({ publicKey });
        return JSON.stringify(credential.toJSON());
    }
};
