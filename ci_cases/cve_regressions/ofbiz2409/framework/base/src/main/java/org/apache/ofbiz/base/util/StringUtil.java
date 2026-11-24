/*******************************************************************************
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *******************************************************************************/
package org.apache.ofbiz.base.util;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.ofbiz.base.lang.IsEmpty;

/**
 * Misc String Utility Functions
 *
 */
public final class StringUtil {

    public static final StringUtil INSTANCE = new StringUtil();
    private static final String MODULE = StringUtil.class.getName();
    private static final Map<String, Pattern> SUBSTITUTION_PATTERN_MAP = createSubstitutionPatternMap();

    private static Map<String, Pattern> createSubstitutionPatternMap() {
        Map<String, Pattern> substitutionPatternMap = new LinkedHashMap<>();  // Preserve insertion order
        substitutionPatternMap.put("&&", Pattern.compile("@and", Pattern.LITERAL));
        substitutionPatternMap.put("||", Pattern.compile("@or", Pattern.LITERAL));
        substitutionPatternMap.put("<=", Pattern.compile("@lteq", Pattern.LITERAL));
        substitutionPatternMap.put(">=", Pattern.compile("@gteq", Pattern.LITERAL));
        substitutionPatternMap.put("<", Pattern.compile("@lt", Pattern.LITERAL));
        substitutionPatternMap.put(">", Pattern.compile("@gt", Pattern.LITERAL));
        return Collections.unmodifiableMap(substitutionPatternMap);
    }

    private StringUtil() {
    }

    public static String internString(String value) {
        return value != null ? value.intern() : null;
    }

    /**
     * Replaces all occurrences of oldString in mainString with newString
     * @param mainString The original string
     * @param oldString The string to replace
     * @param newString The string to insert in place of the old
     * @return mainString with all occurrences of oldString replaced by newString
     */
    public static String replaceString(String mainString, String oldString, String newString) {
        if (mainString == null) {
            return null;
        }
        if (UtilValidate.isEmpty(oldString)) {
            return mainString;
        }
        if (newString == null) {
            newString = "";
        }

        int i = mainString.lastIndexOf(oldString);

        if (i < 0) {
            return mainString;
        }

        StringBuilder mainSb = new StringBuilder(mainString);

        while (i >= 0) {
            mainSb.replace(i, i + oldString.length(), newString);
            i = mainString.lastIndexOf(oldString, i - 1);
        }
        return mainSb.toString();
    }

    /**
     * Creates a single string from a Collection of strings separated by a delimiter.
     * @param col  a collection of strings to join
     * @param delim  the delimiter character(s) to use. (null value will join with no delimiter)
     * @return a String of all values in the collection separated by the delimiter
     */
    public static String join(Collection<?> col, CharSequence delim) {
        return UtilValidate.isEmpty(col)
                ? null
                : col.stream().map(Object::toString).collect(Collectors.joining(delim));
    }

    /**
     * Splits a String on a delimiter into a List of Strings.
     * @param str the String to split
     * @param delim the delimiter character(s) to join on (null will split on whitespace)
     * @return a list of Strings
     */
    public static List<String> split(String str, String delim) {
        List<String> splitList = null;
        StringTokenizer st;

        if (str == null) {
            return null;
        }

        st = (delim != null ? new StringTokenizer(str, delim) : new StringTokenizer(str));

        if (st.hasMoreTokens()) {
            splitList = new LinkedList<>();

            while (st.hasMoreTokens()) {
                splitList.add(st.nextToken());
            }
        }
        return splitList;
    }

    /**
     * Splits a String on a String Separator into a List of Strings.
     * @param str the String to split
     * @param separator the String Separator to split the str String
     * @return a list of Strings or null if one of the parameters is null
     */
    public static List<String> splitWithStringSeparator(String str, String separator) {
        if (str == null || separator == null) {
            return null;
        }

        return Arrays.asList(str.split(separator));
    }

    /**
     * Creates a Map from an encoded name/value pair string
     * @param str The string to decode and format
     * @param delim the delimiter character(s) to join on (null will split on whitespace)
     * @param trim Trim whitespace off fields
     * @return a Map of name/value pairs
     */
    public static Map<String, String> strToMap(String str, String delim, boolean trim) {
        return strToMap(str, delim, trim, null);

    }

    /**
     * Creates a Map from a name/value pair string
     * @param str The string to decode and format
     * @param delim the delimiter character(s) to join on (null will split on whitespace)
     * @param trim Trim whitespace off fields
     * @param pairsSeparator in case you use not encoded name/value pairs strings
     *        and want to replace "=" to avoid clashes with parameters values in a not encoded URL, default to "="
     * @return a Map of name/value pairs
     */
    public static Map<String, String> strToMap(String str, String delim, boolean trim, String pairsSeparator) {
        if (UtilValidate.isEmpty(str)) {
            return null;
        }
        Map<String, String> decodedMap = new HashMap<>();
        List<String> elements = split(str, delim);
        pairsSeparator = pairsSeparator == null ? "=" : pairsSeparator;

        for (String s: elements) {

            List<String> e = split(s, pairsSeparator);
            if (e.size() != 2) {
                continue;
            }
            String name = e.get(0);
            String value = e.get(1);
            if (trim) {
                if (name != null) {
                    name = name.trim();
                }
                if (value != null) {
                    value = value.trim();
                }
            }

            try {
                if (value != null && name != null) {
                    decodedMap.put(URLDecoder.decode(name, "UTF-8"), URLDecoder.decode(value, "UTF-8"));
                }
            } catch (UnsupportedEncodingException e1) {
                Debug.logError(e1, MODULE);
            }
        }
        return decodedMap;
    }

    /**
     * Creates a Map from an encoded name/value pair string
     * @param str The string to decode and format
     * @param trim Trim whitespace off fields
     * @return a Map of name/value pairs
     */
    public static Map<String, String> strToMap(String str, boolean trim) {
        return strToMap(str, "|", trim);
    }

    /**
     * Creates a Map from an encoded name/value pair string
     * @param str The string to decode and format
     * @return a Map of name/value pairs
     */
    public static Map<String, String> strToMap(String str) {
        return strToMap(str, "|", false);
    }

    /**
     * Reads a String version of a List (should contain only strings) and creates a new List
     * @param s String value of a Map ({n1=v1, n2=v2})
     * @return new List
     */
    public static List<String> toList(String s) {
        List<String> newList = new LinkedList<>();
        if (s.startsWith("[") && s.endsWith("]")) {
            s = s.substring(1, s.length() - 1);
            String[] entries = s.split("\\,\\s");
            for (String entry: entries) {
                newList.add(entry);
            }
        } else {
            throw new IllegalArgumentException("String is not from List.toString()");
        }

        return newList;
    }

    /**
     * Reads a String version of a Set (should contain only strings) and creates a new Set
     * @param s String value of a Map ({n1=v1, n2=v2})
     * @return new List
     */
    public static Set<String> toSet(String s) {
        Set<String> newSet = new LinkedHashSet<>();
        if (s.startsWith("[") && s.endsWith("]")) {
            s = s.substring(1, s.length() - 1);
            String[] entries = s.split("\\,\\s");
            for (String entry: entries) {
                newSet.add(entry);
            }
        } else {
            throw new IllegalArgumentException("String is not from Set.toString()");
        }

        return newSet;
    }

    /**
     * Create a Map from a List of keys and a List of values
     * @param keys List of keys
     * @param values List of values
     * @return Map of combined lists
     * @throws IllegalArgumentException When either List is null or the sizes do not equal
     */
    public static <K, V> Map<K, V> createMap(List<K> keys, List<V> values) {
        if (keys == null || values == null || keys.size() != values.size()) {
            throw new IllegalArgumentException("Keys and Values cannot be null and must be the same size");
        }
        Map<K, V> newMap = new HashMap<>();
        for (int i = 0; i < keys.size(); i++) {
            newMap.put(keys.get(i), values.get(i));
        }
        return newMap;
    }

    /** Make sure the string starts with a forward slash but does not end with one; converts back-slashes to forward-slashes;
     * if in String is null or empty, returns zero length string. */
    public static String cleanUpPathPrefix(String prefix) {
        if (UtilValidate.isEmpty(prefix)) {
            return "";
        }

        StringBuilder cppBuff = new StringBuilder(prefix.replace('\\', '/'));

        if (cppBuff.charAt(0) != '/') {
            cppBuff.insert(0, '/');
        }
        if (cppBuff.charAt(cppBuff.length() - 1) == '/') {
            cppBuff.deleteCharAt(cppBuff.length() - 1);
        }
        return cppBuff.toString();
    }

    /** Removes all spaces from a string */
    public static String removeSpaces(String str) {
        return removeRegex(str, "[\\ ]");
    }

    public static String toHexString(byte[] bytes) {
        return new String(Hex.encodeHex(bytes));
    }

    public static String cleanHexString(String str) {
        StringBuilder buf = new StringBuilder();
        for (int i = 0; i < str.length(); i++) {
            if (str.charAt(i) != 32 && str.charAt(i) != ':') {
                buf.append(str.charAt(i));
            }
        }
        return buf.toString();
    }

    public static byte[] fromHexString(String str) {
        str = cleanHexString(str);
        try {
            return Hex.decodeHex(str.toCharArray());
        } catch (DecoderException e) {
            throw new GeneralRuntimeException(e);
        }
    }

    private static char[] hexChar = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    public static char[] encodeInt(int i, int j, char digestChars[]) {
        if (i < 16) {
            digestChars[j] = '0';
        }
        j++;
        do {
            digestChars[j--] = hexChar[i & 0xf];
            i >>>= 4;
        } while (i != 0);
        return digestChars;
    }

    /** Removes all non-numbers from str */
    public static String removeNonNumeric(String str) {
        return removeRegex(str, "[\\D]");
    }

    /**
     * @param str
     * @param regex
     * Removes all matches of regex from a str
     */
    public static String removeRegex(String str, String regex) {
        return str.replaceAll(regex, "");
    }

    /**
     * Add the number to the string, keeping (padding to min of original length)
     * @return the new value
     */
    public static String addToNumberString(String numberString, long addAmount) {
        if (numberString == null) {
            return null;
        }
        int origLength = numberString.length();
        long number = Long.parseLong(numberString);
        return padNumberString(Long.toString(number + addAmount), origLength);
    }

    public static String padNumberString(String numberString, int targetMinLength) {
        StringBuilder outStrBfr = new StringBuilder(numberString);
        while (targetMinLength > outStrBfr.length()) {
            outStrBfr.insert(0, '0');
        }
        return outStrBfr.toString();
    }

    /** Converts operator substitutions (@and, @or, etc) back to their original form.
     * <p>OFBiz script syntax provides special forms of common operators to make
     * it easier to embed logical expressions in XML</p>
     * <table>
     *   <caption>OFBiz XML operators</caption>
     *   <tr><th>OFBiz operator</th><th>Substitution</th></tr>
     *   <tr><td><strong>@and</strong></td><td>&amp;&amp;</td></tr>
     *   <tr><td><strong>@or</strong></td><td>||</td></tr>
     *   <tr><td><strong>@gt</strong></td><td>&gt;</td></tr>
     *   <tr><td><strong>@gteq</strong></td><td>&gt;=</td></tr>
     *   <tr><td><strong>@lt</strong></td><td>&lt;</td></tr>
     *   <tr><td><strong>@lteq</strong></td><td>&lt;=</td></tr>
     * </table>
     * @param expression The <code>String</code> to convert
     * @return The converted <code>String</code>
     */
    public static String convertOperatorSubstitutions(String expression) {
        String result = expression;
        if (result != null && (result.contains("@"))) {
            for (Map.Entry<String, Pattern> entry: SUBSTITUTION_PATTERN_MAP.entrySet()) {
                Pattern pattern = entry.getValue();
                result = pattern.matcher(result).replaceAll(entry.getKey());
            }
            if (Debug.verboseOn()) {
                Debug.logVerbose("Converted " + expression + " to " + result, MODULE);
            }
        }
        return result;
    }

    public static StringWrapper wrapString(String theString) {
        return makeStringWrapper(theString);
    }
    public static StringWrapper makeStringWrapper(String theString) {
        if (theString == null) {
            return null;
        }
        if (theString.isEmpty()) {
            return StringWrapper.EMPTY_STRING_WRAPPER;
        }
        return new StringWrapper(theString);
    }

    /**
     * A super-lightweight object to wrap a String object. Mainly used with FTL
     * templates to avoid the general HTML auto-encoding that is now done through
     * the Screen Widget.
     */
    public static class StringWrapper implements IsEmpty {
        public static final StringWrapper EMPTY_STRING_WRAPPER = new StringWrapper("");

        private String theString;

        protected StringWrapper() {
        }

        public StringWrapper(String theString) {
            this.theString = theString;
        }

        /**
         * Fairly simple method used for the plus (+) base concatenation in Groovy.
         *
         * @param value
         * @return the wrapped string, plus the value
         */
        public String plus(Object value) {
            return this.theString + value;
        }

        /**
         * @return The String this object wraps.
         */
        @Override
        public String toString() {
            return this.theString;
        }

        /**
         * @return true, if wrapped string is null or empty; false otherwise
         */
        @Override
        public boolean isEmpty() {
            return (theString == null || theString.isEmpty());
        }
    }
}
