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
package org.apache.ofbiz.base.util.string;

import java.io.Serializable;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;

import javax.el.PropertyNotFoundException;

import org.apache.ofbiz.base.lang.IsEmpty;
import org.apache.ofbiz.base.lang.SourceMonitored;
import org.apache.ofbiz.base.util.Debug;
import org.apache.ofbiz.base.util.GeneralException;
import org.apache.ofbiz.base.util.ObjectType;
import org.apache.ofbiz.base.util.ScriptUtil;
import org.apache.ofbiz.base.util.UtilDateTime;
import org.apache.ofbiz.base.util.UtilFormatOut;
import org.apache.ofbiz.base.util.UtilGenerics;
import org.apache.ofbiz.base.util.UtilMisc;
import org.apache.ofbiz.base.util.UtilValidate;
import org.apache.ofbiz.base.util.cache.UtilCache;

/** Expands String values that contain Unified Expression Language (JSR 245)
 * syntax. This class also supports the execution of Groovy scripts
 * by using the 'groovy:' prefix.
 * Further it is possible to control the output by specifying the suffix
 * '?currency(XXX)' to format the output according to the supplied locale
 * and specified (XXX) currency.<p>This class extends the UEL by allowing
 * nested expressions.</p>
 */
@SourceMonitored
@SuppressWarnings("serial")
public abstract class FlexibleStringExpander implements Serializable, IsEmpty {

    private static final String MODULE = FlexibleStringExpander.class.getName();
    public static final String OPEN_BRACKET = "${";
    public static final String CLOSE_BRACKET = "}";
    private static final UtilCache<Key, FlexibleStringExpander> EXPR_CACHE = UtilCache.createUtilCache("flexibleStringExpander.ExpressionCache");
    private static final FlexibleStringExpander NULL_EXPR = new ConstSimpleElem(new char[0]);

    /**
     * Returns <code>true</code> if <code>fse</code> contains a <code>String</code> constant.
     * @param fse The <code>FlexibleStringExpander</code> to test
     * @return <code>true</code> if <code>fse</code> contains a <code>String</code> constant
     */
    public static boolean containsConstant(FlexibleStringExpander fse) {
        if (fse instanceof ConstSimpleElem || fse instanceof ConstOffsetElem) {
            return true;
        }
        if (fse instanceof Elements) {
            Elements fseElements = (Elements) fse;
            for (FlexibleStringExpander childElement : fseElements.childElems) {
                if (containsConstant(childElement)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Returns <code>true</code> if <code>fse</code> contains an expression.
     * @param fse The <code>FlexibleStringExpander</code> to test
     * @return <code>true</code> if <code>fse</code> contains an expression
     */
    public static boolean containsExpression(FlexibleStringExpander fse) {
        return !(fse instanceof ConstSimpleElem);
    }

    /**
     * Returns <code>true</code> if <code>fse</code> contains a script.
     * @param fse The <code>FlexibleStringExpander</code> to test
     * @return <code>true</code> if <code>fse</code> contains a script
     */
    public static boolean containsScript(FlexibleStringExpander fse) {
        if (fse instanceof ScriptElem) {
            return true;
        }
        if (fse instanceof Elements) {
            Elements fseElements = (Elements) fse;
            for (FlexibleStringExpander childElement : fseElements.childElems) {
                if (containsScript(childElement)) {
                    return true;
                }
            }
        }
        return false;
    }

    /** Evaluate an expression and return the result as a <code>String</code>.
     * Null expressions return <code>null</code>.
     * A null <code>context</code> argument will return the original expression.
     * <p>Note that the behavior of this method is not the same as using
     * <code>FlexibleStringExpander.getInstance(expression).expandString(context)</code>
     * because it returns <code>null</code> when given a null <code>expression</code>
     * argument, and
     * <code>FlexibleStringExpander.getInstance(expression).expandString(context)</code>
     * returns an empty <code>String</code>.</p>
     * @param expression The original expression
     * @param context The evaluation context
     * @return The original expression's evaluation result as a <code>String</code>
     */
    public static String expandString(String expression, Map<String, ? extends Object> context) {
        return expandString(expression, context, null, null);
    }

    /** Evaluate an expression and return the result as a <code>String</code>.
     * Null expressions return <code>null</code>.
     * A null <code>context</code> argument will return the original expression.
     * <p>Note that the behavior of this method is not the same as using
     * <code>FlexibleStringExpander.getInstance(expression).expandString(context, locale)</code>
     * because it returns <code>null</code> when given a null <code>expression</code>
     * argument, and
     * <code>FlexibleStringExpander.getInstance(expression).expandString(context, locale)</code>
     * returns an empty <code>String</code>.</p>
     * @param expression The original expression
     * @param context The evaluation context
     * @param locale The locale to be used for localization
     * @return The original expression's evaluation result as a <code>String</code>
     */
    public static String expandString(String expression, Map<String, ? extends Object> context, Locale locale) {
        return expandString(expression, context, null, locale);
    }

    /** Evaluate an expression and return the result as a <code>String</code>.
     * Null expressions return <code>null</code>.
     * A null <code>context</code> argument will return the original expression.
     * <p>Note that the behavior of this method is not the same as using
     * <code>FlexibleStringExpander.getInstance(expression).expandString(context, timeZone locale)</code>
     * because it returns <code>null</code> when given a null <code>expression</code>
     * argument, and
     * <code>FlexibleStringExpander.getInstance(expression).expandString(context, timeZone, locale)</code>
     * returns an empty <code>String</code>.</p>
     * @param expression The original expression
     * @param context The evaluation context
     * @param timeZone The time zone to be used for localization
     * @param locale The locale to be used for localization
     * @return The original expression's evaluation result as a <code>String</code>
     */
    public static String expandString(String expression, Map<String, ? extends Object> context, TimeZone timeZone, Locale locale) {
        if (expression == null) {
            return "";
        }
        if (context == null || !expression.contains(OPEN_BRACKET)) {
            return expression;
        }
        FlexibleStringExpander fse = FlexibleStringExpander.getInstance(expression);
        return fse.expandString(context, timeZone, locale);
    }

    /** Returns a <code>FlexibleStringExpander</code> object. <p>A null or
     * empty argument will return a <code>FlexibleStringExpander</code>
     * object that represents an empty expression. That object is a shared
     * singleton, so there is no memory or performance penalty in using it.</p>
     * <p>If the method is passed a <code>String</code> argument that doesn't
     * contain an expression, the <code>FlexibleStringExpander</code> object
     * that is returned does not perform any evaluations on the original
     * <code>String</code> - any methods that return a <code>String</code>
     * will return the original <code>String</code>. The object returned by
     * this method is very compact - taking less memory than the original
     * <code>String</code>.</p>
     * @param expression The original expression
     * @return A <code>FlexibleStringExpander</code> instance
     */
    public static FlexibleStringExpander getInstance(String expression) {
        return getInstance(expression, true);
    }

    /* Returns a <code>FlexibleStringExpander</code> object. <p>A null or
     * empty argument will return a <code>FlexibleStringExpander</code>
     * object that represents an empty expression. That object is a shared
     * singleton, so there is no memory or performance penalty in using it.</p>
     * <p>If the method is passed a <code>String</code> argument that doesn't
     * contain an expression, the <code>FlexibleStringExpander</code> object
     * that is returned does not perform any evaluations on the original
     * <code>String</code> - any methods that return a <code>String</code>
     * will return the original <code>String</code>. The object returned by
     * this method is very compact - taking less memory than the original
     * <code>String</code>.</p>
     * @param expression The original expression
     * @param useCache whether to store things into a global cache
     * @return A <code>FlexibleStringExpander</code> instance
     */
    public static FlexibleStringExpander getInstance(String expression, boolean useCache) {
        if (UtilValidate.isEmpty(expression)) {
            return NULL_EXPR;
        }
        return getInstance(expression, expression.toCharArray(), 0, expression.length(), useCache);
    }

    private static FlexibleStringExpander getInstance(String expression, char[] chars, int offset, int length, boolean useCache) {
        if (length == 0) {
            return NULL_EXPR;
        }
        if (!useCache) {
            return parse(chars, offset, length);
        }
        // Remove the next nine lines to cache all expressions
        if (!expression.contains(OPEN_BRACKET)) {
            if (chars.length == length) {
                return new ConstSimpleElem(chars);
            } else {
                return new ConstOffsetElem(chars, offset, length);
            }
        }
        Key key = chars.length == length ? new SimpleKey(chars) : new OffsetKey(chars, offset, length);
        FlexibleStringExpander fse = EXPR_CACHE.get(key);
        if (fse == null) {
            EXPR_CACHE.put(key, parse(chars, offset, length));
            fse = EXPR_CACHE.get(key);
        }
        return fse;
    }

    private abstract static class Key {
        @Override
        public final boolean equals(Object o) {
            // No class test here, nor null, as this class is only used internally
            return (o == null) ? false : toString().equals(o.toString());
        }

        @Override
        public final int hashCode() {
            return toString().hashCode();
        }
    }

    private static final class SimpleKey extends Key {
        private final char[] chars;

        protected SimpleKey(char[] chars) {
            this.chars = chars;
        }

        @Override
        public String toString() {
            return new String(chars);
        }
    }

    private static final class OffsetKey extends Key {
        private final char[] chars;
        private final int offset;
        private final int length;

        protected OffsetKey(char[] chars, int offset, int length) {
            this.chars = chars;
            this.offset = offset;
            this.length = length;
        }

        @Override
        public String toString() {
            return new String(chars, offset, length);
        }
    }

    private static FlexibleStringExpander parse(char[] chars, int offset, int length) {
        FlexibleStringExpander[] strElems = getStrElems(chars, offset, length);
        if (strElems.length == 1) {
            return strElems[0];
        } else {
            return new Elements(chars, offset, length, strElems);
        }
    }

    protected static FlexibleStringExpander[] getStrElems(char[] chars, int offset, int length) {
        String expression = new String(chars, 0, length + offset);
        int start = expression.indexOf(OPEN_BRACKET, offset);
        if (start == -1) {
            return new FlexibleStringExpander[] {new ConstOffsetElem(chars, offset, length) };
        }
        int origLen = length;
        ArrayList<FlexibleStringExpander> strElems = new ArrayList<>();
        int currentInd = offset;
        int end = -1;
        while (start != -1) {
            end = expression.indexOf(CLOSE_BRACKET, start);
            if (end == -1) {
                Debug.logWarning("Found a ${ without a closing } (curly-brace) in the String: " + expression, MODULE);
                break;
            }
            // Check for escaped expression
            boolean escapedExpression = (start - 1 >= 0 && expression.charAt(start - 1) == '\\');
            if (start > currentInd) {
                // append everything from the current index to the start of the expression
                strElems.add(new ConstOffsetElem(chars, currentInd, (escapedExpression ? start - 1 : start) - currentInd));
            }
            if (expression.indexOf("groovy:", start + 2) == start + 2 && !escapedExpression) {
                // checks to see if this starts with a "groovy:", if so treat the rest of the expression as a groovy scriptlet
                end = getMatchingClosingBracket(expression, start, origLen, end);
                strElems.add(new ScriptElem(chars, start, Math.min(end + 1, start + length) - start, start + 9, end - start - 9));
            } else {
                // Scan for matching closing bracket
                end = getMatchingClosingBracket(expression, start, origLen, end);
                // Evaluation sequence is important - do not change it
                if (escapedExpression) {
                    strElems.add(new ConstOffsetElem(chars, start, end + 1 - start));
                } else {
                    String subExpression = expression.substring(start + 2, end);
                    int currencyPos = subExpression.indexOf("?currency(");
                    int closeParen = currencyPos > 0 ? subExpression.indexOf(")", currencyPos + 10) : -1;
                    if (closeParen != -1) {
                        strElems.add(new CurrElem(chars, start, Math.min(end + 1, start + length) - start, start + 2, end - start - 1));
                    } else if (subExpression.contains(OPEN_BRACKET)) {
                        strElems.add(new NestedVarElem(chars, start, Math.min(end + 1, start + length) - start, start + 2,
                                Math.min(end - 2, start + length) - start));
                    } else {
                        strElems.add(new VarElem(chars, start, Math.min(end + 1, start + length) - start, start + 2,
                                Math.min(end - 2, start + length) - start));
                    }
                }
            }
            // reset the current index to after the expression, and the start to the beginning of the next expression
            currentInd = end + 1;
            if (currentInd > origLen + offset) {
                currentInd = origLen + offset;
            }
            start = expression.indexOf(OPEN_BRACKET, currentInd);
        }
        // append the rest of the original string, ie after the last expression
        if (currentInd < origLen + offset) {
            strElems.add(new ConstOffsetElem(chars, currentInd, offset + length - currentInd));
        }
        return strElems.toArray(new FlexibleStringExpander[strElems.size()]);
    }

    private static int getMatchingClosingBracket(String expression, int start, int origLen, int end) {
        int ptr = expression.indexOf("{", start + 2);
        while (ptr != -1 && end != -1 && ptr < end) {
            end = expression.indexOf(CLOSE_BRACKET, end + 1);
            ptr = expression.indexOf("{", ptr + 1);
        }
        if (end == -1) {
            end = origLen;
        }
        return end;
    }

    // Note: a character array is used instead of a String to keep the memory footprint small.
    private final char[] chars;
    private int hint = 20;

    /**
     * Get chars char [ ].
     * @return the char [ ]
     */
    public char[] getChars() {
        return chars;
    }

    /**
     * Gets hint.
     * @return the hint
     */
    public int getHint() {
        return hint;
    }

    /**
     * Sets hint.
     * @param hint the hint
     */
    public void setHint(int hint) {
        this.hint = hint;
    }

    protected FlexibleStringExpander(char[] chars) {
        this.chars = chars;
    }

    protected abstract Object get(Map<String, ? extends Object> context, TimeZone timeZone, Locale locale);

    private static Locale getLocale(Locale locale, Map<String, ? extends Object> context) {
        if (locale == null) {
            locale = (Locale) context.get("locale");
            if (locale == null && context.containsKey("autoUserLogin")) {
                Map<String, Object> autoUserLogin = UtilGenerics.cast(context.get("autoUserLogin"));
                locale = UtilMisc.ensureLocale(autoUserLogin.get("lastLocale"));
            }
            if (locale == null && context.containsKey(UelUtil.getLocalizedMapLocaleKey())) {
                locale = UtilMisc.ensureLocale(context.get(UelUtil.getLocalizedMapLocaleKey()));
            }
            if (locale == null) {
                locale = Locale.getDefault();
            }
        }
        return locale;
    }

    private static TimeZone getTimeZone(TimeZone timeZone, Map<String, ? extends Object> context) {
        if (timeZone == null) {
            timeZone = (TimeZone) context.get("timeZone");
            if (timeZone == null && context.containsKey("autoUserLogin")) {
                Map<String, String> autoUserLogin = UtilGenerics.cast(context.get("autoUserLogin"));
                timeZone = UtilDateTime.toTimeZone(autoUserLogin.get("lastTimeZone"));
            }
            if (timeZone == null) {
                timeZone = TimeZone.getDefault();
            }
        }
        return timeZone;
    }

    /** Evaluate this object's expression and return the result as a <code>String</code>.
     * Null or empty expressions return an empty <code>String</code>.
     * A <code>null context</code> argument will return the original expression.
     * @param context The evaluation context
     * @return This object's expression result as a <code>String</code>
     */
    public String expandString(Map<String, ? extends Object> context) {
        return this.expandString(context, null, null);
    }

    /** Evaluate this object's expression and return the result as a <code>String</code>.
     * Null or empty expressions return an empty <code>String</code>.
     * A <code>null context</code> argument will return the original expression.
     * @param context The evaluation context
     * @param locale The locale to be used for localization
     * @return This object's expression result as a <code>String</code>
     */
    public String expandString(Map<String, ? extends Object> context, Locale locale) {
        return this.expandString(context, null, locale);
    }

    /** Evaluate this object's expression and return the result as a <code>String</code>.
     * Null or empty expressions return an empty <code>String</code>.
     * A <code>null context</code> argument will return the original expression.
     * @param context The evaluation context
     * @param timeZone The time zone to be used for localization
     * @param locale The locale to be used for localization
     * @return This object's expression result as a <code>String</code>
     */
    public String expandString(Map<String, ? extends Object> context, TimeZone timeZone, Locale locale) {
        if (context == null) {
            return this.toString();
        }
        timeZone = getTimeZone(timeZone, context);
        locale = getLocale(locale, context);
        Object obj = get(context, timeZone, locale);
        StringBuilder buffer = new StringBuilder(this.hint);
        try {
            if (obj != null) {
                if (obj instanceof String) {
                    buffer.append(obj);
                } else {
                    buffer.append(ObjectType.simpleTypeOrObjectConvert(obj, "String", null, timeZone, locale, true));
                }
            }
        } catch (GeneralException | RuntimeException e) {
            Debug.log(e, MODULE);
            buffer.append(obj);
        }
        if (buffer.length() > this.hint) {
            this.hint = buffer.length();
        }
        return buffer.toString();
    }

    /** Evaluate this object's expression and return the result as an <code>Object</code>.
     * Null or empty expressions return an empty <code>String</code>.
     * A <code>null context</code> argument will return the original expression.
     * @param context The evaluation context
     * @return This object's expression result as a <code>String</code>
     */
    public Object expand(Map<String, ? extends Object> context) {
        return this.expand(context, null, null);
    }

    /** Evaluate this object's expression and return the result as an <code>Object</code>.
     * Null or empty expressions return an empty <code>String</code>.
     * A <code>null context</code> argument will return the original expression.
     * @param context The evaluation context
     * @param locale The locale to be used for localization
     * @return This object's expression result as a <code>String</code>
     */
    public Object expand(Map<String, ? extends Object> context, Locale locale) {
        return this.expand(context, null, locale);
    }

    /** Evaluate this object's expression and return the result as an <code>Object</code>.
     * Null or empty expressions return an empty <code>String</code>.
     * A <code>null context</code> argument will return the original expression.
     * @param context The evaluation context
     * @param timeZone The time zone to be used for localization
     * @param locale The locale to be used for localization
     * @return This object's expression result as a <code>String</code>
     */
    public Object expand(Map<String, ? extends Object> context, TimeZone timeZone, Locale locale) {
        if (context == null) {
            return null;
        }
        return get(context, getTimeZone(timeZone, context), getLocale(locale, context));
    }

    /** Returns a copy of the original expression.
     * @return The original expression
     */
    public abstract String getOriginal();

    /** Returns <code>true</code> if the original expression is empty
     * or <code>null</code>.
     * @return <code>true</code> if the original expression is empty
     * or <code>null</code>
     */
    @Override
    public abstract boolean isEmpty();

    /** Returns a copy of the original expression.
     * @return The original expression
     */
    @Override
    public String toString() {
        return this.getOriginal();
    }

    protected abstract static class ArrayOffsetString extends FlexibleStringExpander {
        private final int offset;
        private final int length;
        /**
         * Gets length.
         * @return the length
         */
        public int getLength() {
            return length;
        }
        /**
         * Gets offset.
         * @return the offset
         */
        public int getOffset() {
            return offset;
        }

        protected ArrayOffsetString(char[] chars, int offset, int length) {
            super(chars);
            this.offset = offset;
            this.length = length;
        }
        @Override
        public boolean isEmpty() {
            // This is always false; the complex child classes can't be
            // empty, as they contain at least ${; constant elements
            // with a length of 0 will never be created.
            return false;
        }
        @Override
        public String getOriginal() {
            return new String(this.getChars(), this.offset, this.length);
        }
    }

    /** An object that represents a <code>String</code> constant portion of an expression. */
    protected static class ConstSimpleElem extends FlexibleStringExpander {
        protected ConstSimpleElem(char[] chars) {
            super(chars);
        }

        @Override
        public boolean isEmpty() {
            return this.getChars().length == 0;
        }

        @Override
        public String getOriginal() {
            return new String(this.getChars());
        }

        @Override
        public String expandString(Map<String, ? extends Object> context, TimeZone timeZone, Locale locale) {
            return getOriginal();
        }

        @Override
        protected Object get(Map<String, ? extends Object> context, TimeZone timeZone, Locale locale) {
            return isEmpty() ? null : getOriginal();
        }
    }

    /** An object that represents a <code>String</code> constant portion of an expression. */
    protected static class ConstOffsetElem extends ArrayOffsetString {
        protected ConstOffsetElem(char[] chars, int offset, int length) {
            super(chars, offset, length);
        }

        @Override
        protected Object get(Map<String, ? extends Object> context, TimeZone timeZone, Locale locale) {
            return getOriginal();
        }

        @Override
        public String expandString(Map<String, ? extends Object> context, TimeZone timeZone, Locale locale) {
            return new String(this.getChars(), this.getOffset(), this.getLength());
        }
    }

    /** An object that represents a currency portion of an expression. */
    protected static class CurrElem extends ArrayOffsetString {
        private final char[] valueStr;
        private final FlexibleStringExpander codeExpr;

        protected CurrElem(char[] chars, int offset, int length, int parseStart, int parseLength) {
            super(chars, offset, length);
            String parse = new String(chars, parseStart, parseLength);
            int currencyPos = parse.indexOf("?currency(");
            int closeParen = parse.indexOf(")", currencyPos + 10);
            this.codeExpr = FlexibleStringExpander.getInstance(parse, chars, parseStart + currencyPos + 10, closeParen - currencyPos - 10,
                    true);
            this.valueStr = OPEN_BRACKET.concat(parse.substring(0, currencyPos)).concat(CLOSE_BRACKET).toCharArray();
        }

        @Override
        protected Object get(Map<String, ? extends Object> context, TimeZone timeZone, Locale locale) {
            try {
                Object obj = UelUtil.evaluate(context, new String(this.valueStr));
                if (obj != null) {
                    String currencyCode = this.codeExpr.expandString(context, timeZone, locale);
                    return UtilFormatOut.formatCurrency(new BigDecimal(obj.toString()), currencyCode, locale);
                }
            } catch (PropertyNotFoundException e) {
                if (Debug.verboseOn()) {
                    Debug.logVerbose("Error evaluating expression: " + e, MODULE);
                }
            } catch (Exception e) {
                Debug.logError("Error evaluating expression: " + e, MODULE);
            }
            return null;
        }
    }

    /** A container object that contains expression fragments. */
    protected static class Elements extends ArrayOffsetString {
        private final FlexibleStringExpander[] childElems;

        protected Elements(char[] chars, int offset, int length, FlexibleStringExpander[] childElems) {
            super(chars, offset, length);
            this.childElems = childElems;
        }

        @Override
        protected Object get(Map<String, ? extends Object> context, TimeZone timeZone, Locale locale) {
            StringBuilder buffer = new StringBuilder();
            for (FlexibleStringExpander child : this.childElems) {
                buffer.append(child.expandString(context, timeZone, locale));
            }
            return buffer.toString();
        }
    }

    /** An object that represents a <code>${[groovy|bsh]:}</code> expression. */
    protected static class ScriptElem extends ArrayOffsetString {
        private final String language;
        private final int parseStart;
        private final int parseLength;
        private final String script;
        private final Class<?> parsedScript;

        protected ScriptElem(char[] chars, int offset, int length, int parseStart, int parseLength) {
            super(chars, offset, length);
            this.language = new String(this.getChars(), offset + 2, parseStart - offset - 3);
            this.parseStart = parseStart;
            this.parseLength = parseLength;
            this.script = new String(this.getChars(), this.parseStart, this.parseLength);
            this.parsedScript = ScriptUtil.parseScript(this.language, this.script);
        }

        @Override
        protected Object get(Map<String, ? extends Object> context, TimeZone timeZone, Locale locale) {
            try {
                Map<String, Object> contextCopy = new HashMap<>(context);
                Object obj = ScriptUtil.evaluate(this.language, this.script, this.parsedScript, contextCopy);
                if (obj != null) {
                    return obj;
                } else {
                    if (Debug.verboseOn()) {
                        Debug.logVerbose("Scriptlet evaluated to null [" + this + "].", MODULE);
                    }
                }
            } catch (Exception e) {
                Debug.logWarning(e, "Error evaluating scriptlet [" + this + "]; error was: " + e, MODULE);
            }
            return null;
        }
    }

    /** An object that represents a nested expression. */
    protected static class NestedVarElem extends ArrayOffsetString {
        private final FlexibleStringExpander[] childElems;

        protected NestedVarElem(char[] chars, int offset, int length, int parseStart, int parseLength) {
            super(chars, offset, length);
            this.childElems = getStrElems(chars, parseStart, parseLength);
            if (length > this.getHint()) {
                this.setHint(length);
            }
        }

        @Override
        protected Object get(Map<String, ? extends Object> context, TimeZone timeZone, Locale locale) {
            StringBuilder expr = new StringBuilder(this.getHint());
            for (FlexibleStringExpander child : this.childElems) {
                expr.append(child.expandString(context, timeZone, locale));
            }
            if (expr.length() == 0) {
                return "";
            }
            try {
                return UelUtil.evaluate(context, OPEN_BRACKET.concat(expr.toString()).concat(CLOSE_BRACKET));
            } catch (PropertyNotFoundException e) {
                if (Debug.verboseOn()) {
                    Debug.logVerbose("Error evaluating expression: " + e, MODULE);
                }
            } catch (Exception e) {
                Debug.logError("Error evaluating expression: " + e, MODULE);
            }
            return "";
        }
    }

    /** An object that represents a simple, non-nested expression. */
    protected static class VarElem extends ArrayOffsetString {
        private final char[] bracketedOriginal;

        protected VarElem(char[] chars, int offset, int length, int parseStart, int parseLength) {
            super(chars, offset, length);
            this.bracketedOriginal = OPEN_BRACKET.concat(UelUtil.prepareExpression(new String(chars, parseStart, parseLength)))
                    .concat(CLOSE_BRACKET).toCharArray();
        }

        @Override
        protected Object get(Map<String, ? extends Object> context, TimeZone timeZone, Locale locale) {
            Object obj = null;
            try {
                obj = UelUtil.evaluate(context, new String(this.bracketedOriginal));
            } catch (PropertyNotFoundException e) {
                if (Debug.verboseOn()) {
                    Debug.logVerbose("Error evaluating expression " + this + ": " + e, MODULE);
                }
            } catch (Exception e) {
                Debug.logError("Error evaluating expression " + this + ": " + e, MODULE);
            }
            return obj;
        }
    }
}
