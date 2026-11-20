package com.sun.identity.common;

/**
 * CVE-2026-45049 hijack trigger: an all-literal toString() def.
 * Pre-Fix 136 this def's 'safe' summary propagates by bare name onto the
 * language-less external 'toString' placeholder hub, vetoing every
 * StringBuilder/String .toString() argument in the corpus — including
 * CDCServlet's tainted redirectURL chains (L644/L677).
 */
public class HijackToStringSource {

    private final String id;

    public HijackToStringSource(String id) {
        this.id = id;
    }

    @Override
    public String toString() {
        return "HijackToStringSource";
    }
}
