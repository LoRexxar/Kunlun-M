package org.forgerock.openam.services.push.sns;

// CVE-2026-45794 repro — OpenAM unsafe Java deserialization via anonymous
// Push Notification SNS callback (GHSA-pp89-732f-3g8q; fix ca15cba9 adds
// the PUSH_PREDICATES allowlist).  Byte-faithful extract of the vulnerable
// attemptFromCTS chain from SnsMessageResource @07e402c3 (pre-fix); the
// forgerock library types (CTSPersistentStore, Token, JsonValue,
// JsonValueBuilder, JSONSerialisation, Predicate, NotFoundException)
// stay EXTERNAL — like the campaign corpus, where only SnsMessageResource
// is present — so the chain runs through the typed-receiver qualified
// knowledge boundary (Fix 140/140b), not through local bodies.
//
// Chain: anonymous @Action SNS callback -> handle() -> messageId expired
// from the in-memory dispatcher -> attemptFromCTS ->
// CTSPersistentStore.read(messageId) [second-order source: the blob is
// the serialized predicate map an UNAUTHENTICATED flow wrote —
// addRegistrationInfo serialises actionContent straight into
// Token.setBlob] -> getBlob -> JsonValueBuilder.toJsonValue -> asMap ->
// entrySet loop -> entry.getKey() as class name -> Class.forName +
// JSONSerialisation (Jackson) deserialise = arbitrary class load +
// construction.

import java.util.Map;

public class SnsMessageResource {

    private final CTSPersistentStore coreTokenService;
    private final JSONSerialisation jsonSerialisation;

    public Object authenticate(Object context, Object actionRequest) {
        return handle(actionRequest);
    }

    private Object handle(Object actionRequest) {
        Object actionContent = actionRequest;
        String messageId = String.valueOf(actionContent);
        try {
            throw new NotFoundException("messageId expired from dispatcher");
        } catch (NotFoundException e) {
            try {
                attemptFromCTS(messageId, actionContent);
            } catch (Exception ex) {
                return new Object();
            }
        }
        return new Object();
    }

    private boolean attemptFromCTS(String messageId, Object actionContent)
            throws ClassNotFoundException, IllegalAccessException, InstantiationException {
        Token coreToken = coreTokenService.read(messageId);
        byte[] serializedBlob = coreToken.getBlob();
        String fromBlob = new String(serializedBlob);
        JsonValue jsonValue = JsonValueBuilder.toJsonValue(fromBlob);
        Map<String, Object> predicates = jsonValue.asMap();
        for (Map.Entry<String, Object> entry : predicates.entrySet()) {
            String className = entry.getKey();
            Predicate pred =
                    (Predicate) jsonSerialisation.deserialise((String) entry.getValue(), Class.forName(className));
            pred.perform(actionContent);
        }
        return true;
    }
}
