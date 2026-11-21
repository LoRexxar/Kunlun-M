package org.forgerock.openam.services.push.sns;

// Negative controls for CVE-2026-45794 (Fix 140/140b):
//  1) const-origin blob: same sink shape (toJsonValue -> asMap -> getKey
//     -> Class.forName) but the payload is a compile-time constant — the
//     passthrough entries must forward the (absent) taint only, never
//     create a source.  A 6018 row here means a Fix 140b entry turned
//     into a phantom source.
//  2) qualified-only discipline: a DIFFERENT declared type's read()
//     (TokenStore.read — not in the knowledge base) must stay unresolved;
//     a 6018 row here means the CTSPersistentStore.read source leaked
//     into a bare-name "read" match.

import java.util.Map;

public class SnsNegative {

    public boolean attemptConst() throws ClassNotFoundException {
        byte[] serializedBlob = "constant-payload".getBytes();
        String fromBlob = new String(serializedBlob);
        JsonValue jsonValue = JsonValueBuilder.toJsonValue(fromBlob);
        Map<String, Object> predicates = jsonValue.asMap();
        for (Map.Entry<String, Object> entry : predicates.entrySet()) {
            String className = entry.getKey();
            Class.forName(className);
        }
        return true;
    }

    private final TokenStore otherStore;

    public boolean attemptOtherStore(String messageId) throws ClassNotFoundException {
        Token coreToken = otherStore.read(messageId);
        byte[] serializedBlob = coreToken.getBlob();
        String fromBlob = new String(serializedBlob);
        JsonValue jsonValue = JsonValueBuilder.toJsonValue(fromBlob);
        Map<String, Object> predicates = jsonValue.asMap();
        for (Map.Entry<String, Object> entry : predicates.entrySet()) {
            String className = entry.getKey();
            Class.forName(className);
        }
        return true;
    }
}
