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
package org.apache.ofbiz.widget.model;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Set;

import javax.xml.parsers.ParserConfigurationException;

import org.apache.ofbiz.base.util.Debug;
import org.apache.ofbiz.base.util.GeneralException;
import org.apache.ofbiz.base.util.StringUtil;
import org.apache.ofbiz.base.util.UtilCodec;
import org.apache.ofbiz.base.util.UtilGenerics;
import org.apache.ofbiz.base.util.UtilMisc;
import org.apache.ofbiz.base.util.UtilXml;
import org.apache.ofbiz.base.util.collections.MapStack;
import org.apache.ofbiz.base.util.string.FlexibleStringExpander;
import org.apache.ofbiz.entity.Delegator;
import org.apache.ofbiz.entity.GenericEntityException;
import org.apache.ofbiz.entity.GenericValue;
import org.apache.ofbiz.entity.util.EntityQuery;
import org.apache.ofbiz.widget.WidgetFactory;
import org.apache.ofbiz.widget.model.CommonWidgetModels.AutoEntityParameters;
import org.apache.ofbiz.widget.model.CommonWidgetModels.AutoServiceParameters;
import org.apache.ofbiz.widget.model.CommonWidgetModels.Image;
import org.apache.ofbiz.widget.model.CommonWidgetModels.Link;
import org.apache.ofbiz.widget.model.CommonWidgetModels.Parameter;
import org.apache.ofbiz.widget.portal.PortalPageWorker;
import org.apache.ofbiz.widget.renderer.FormRenderer;
import org.apache.ofbiz.widget.renderer.FormStringRenderer;
import org.apache.ofbiz.widget.renderer.MenuStringRenderer;
import org.apache.ofbiz.widget.renderer.ScreenRenderer;
import org.apache.ofbiz.widget.renderer.ScreenStringRenderer;
import org.apache.ofbiz.widget.renderer.TreeStringRenderer;
import org.apache.ofbiz.widget.renderer.VisualTheme;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;


/**
 * Widget Library - Screen model class
 */
@SuppressWarnings("serial")
public abstract class ModelScreenWidget extends ModelWidget {
    private static final String MODULE = ModelScreenWidget.class.getName();

    private final ModelScreen modelScreen;

    public ModelScreenWidget(ModelScreen modelScreen, Element widgetElement) {
        super(widgetElement);
        this.modelScreen = modelScreen;
        if (Debug.verboseOn()) {
            Debug.logVerbose("Reading Screen sub-widget with name: " + widgetElement.getNodeName(), MODULE);
        }
    }

    public abstract void renderWidgetString(Appendable writer, Map<String, Object> context,
                                            ScreenStringRenderer screenStringRenderer) throws GeneralException, IOException;

    protected static List<ModelScreenWidget> readSubWidgets(ModelScreen modelScreen, List<? extends Element> subElementList) {
        if (subElementList.isEmpty()) {
            return Collections.emptyList();
        }
        List<ModelScreenWidget> subWidgets = new ArrayList<>(subElementList.size());
        for (Element subElement: subElementList) {
            subWidgets.add(WidgetFactory.getModelScreenWidget(modelScreen, subElement));
        }
        return Collections.unmodifiableList(subWidgets);
    }

    protected static void renderSubWidgetsString(List<ModelScreenWidget> subWidgets, Appendable writer,
                                                 Map<String, Object> context, ScreenStringRenderer screenStringRenderer)
                                                    throws GeneralException, IOException {
        if (subWidgets == null) {
            return;
        }
        for (ModelScreenWidget subWidget: subWidgets) {
            if (Debug.verboseOn()) {
                Debug.logVerbose("Rendering screen " + subWidget.getModelScreen().getName()
                        + "; widget class is " + subWidget.getClass().getName(), MODULE);
            }

            // render the sub-widget itself
            subWidget.renderWidgetString(writer, context, screenStringRenderer);
        }
    }

    /**
     * Gets model screen.
     * @return the model screen
     */
    public ModelScreen getModelScreen() {
        return this.modelScreen;
    }

    public static final class SectionsRenderer implements Map<String, ModelScreenWidget> {
        private final Map<String, ModelScreenWidget> sectionMap;
        private final ScreenStringRenderer screenStringRenderer;
        private final Map<String, Object> context;
        private final Appendable writer;

        public SectionsRenderer(Map<String, ModelScreenWidget> sectionMap, Map<String, Object> context, Appendable writer,
                ScreenStringRenderer screenStringRenderer) {
            Map<String, ModelScreenWidget> localMap = new HashMap<>();
            localMap.putAll(sectionMap);
            this.sectionMap = Collections.unmodifiableMap(localMap);
            this.context = context;
            this.writer = writer;
            this.screenStringRenderer = screenStringRenderer;
        }

        /** This is a lot like the ScreenRenderer class and returns an empty String so it can be used more easily with FreeMarker */
        public String render(String sectionName) throws GeneralException, IOException {
            ModelScreenWidget section = sectionMap.get(sectionName);
            // if no section by that name, write nothing
            if (section != null) {
                section.renderWidgetString(this.writer, this.context, this.screenStringRenderer);
            }
            return "";
        }

        @Override
        public int size() {
            return sectionMap.size();
        }

        @Override
        public boolean isEmpty() {
            return sectionMap.isEmpty();
        }

        @Override
        public boolean containsKey(Object key) {
            return sectionMap.containsKey(key);
        }

        @Override
        public boolean containsValue(Object value) {
            return sectionMap.containsValue(value);
        }

        @Override
        public ModelScreenWidget get(Object key) {
            return sectionMap.get(key);
        }

        @Override
        public ModelScreenWidget put(String key, ModelScreenWidget value) {
            return sectionMap.put(key, value);
        }

        @Override
        public ModelScreenWidget remove(Object key) {
            return sectionMap.remove(key);
        }

        @Override
        public void clear() {
            sectionMap.clear();
        }

        @Override
        public Set<String> keySet() {
            return sectionMap.keySet();
        }

        @Override
        public Collection<ModelScreenWidget> values() {
            return sectionMap.values();
        }

        @Override
        public Set<java.util.Map.Entry<String, ModelScreenWidget>> entrySet() {
            return sectionMap.entrySet();
        }

        @Override
        public boolean equals(Object o) {
            return sectionMap.equals(o);
        }

        @Override
        public int hashCode() {
            return sectionMap.hashCode();
        }

        @Override
        public void putAll(Map<? extends String, ? extends ModelScreenWidget> m) {
            sectionMap.putAll(m);
        }
    }

    public static final class Section extends ModelScreenWidget {
        public static final String TAG_NAME = "section";
        private final ModelCondition condition;
        private final List<ModelAction> actions;
        private final List<ModelScreenWidget> subWidgets;
        private final List<ModelScreenWidget> failWidgets;
        private final boolean isMainSection;

        public Section(ModelScreen modelScreen, Element sectionElement) {
            this(modelScreen, sectionElement, false);
        }

        public Section(ModelScreen modelScreen, Element sectionElement, boolean isMainSection) {
            super(modelScreen, sectionElement);

            // read condition under the "condition" element
            Element conditionElement = UtilXml.firstChildElement(sectionElement, "condition");
            if (conditionElement != null) {
                conditionElement = UtilXml.firstChildElement(conditionElement);
                this.condition = ModelScreenCondition.SCREEN_CONDITION_FACTORY.newInstance(modelScreen, conditionElement);
            } else {
                this.condition = null;
            }

            // read all actions under the "actions" element
            Element actionsElement = UtilXml.firstChildElement(sectionElement, "actions");
            if (actionsElement != null) {
                this.actions = AbstractModelAction.readSubActions(modelScreen, actionsElement);
            } else {
                this.actions = Collections.emptyList();
            }

            // read sub-widgets
            Element widgetsElement = UtilXml.firstChildElement(sectionElement, "widgets");
            if (widgetsElement != null) {
                List<? extends Element> subElementList = UtilXml.childElementList(widgetsElement);
                this.subWidgets = ModelScreenWidget.readSubWidgets(getModelScreen(), subElementList);
            } else {
                this.subWidgets = Collections.emptyList();
            }

            // read fail-widgets
            Element failWidgetsElement = UtilXml.firstChildElement(sectionElement, "fail-widgets");
            if (failWidgetsElement != null) {
                List<? extends Element> failElementList = UtilXml.childElementList(failWidgetsElement);
                this.failWidgets = ModelScreenWidget.readSubWidgets(getModelScreen(), failElementList);
            } else {
                this.failWidgets = Collections.emptyList();
            }
            this.isMainSection = isMainSection;
        }

        @Override
        public void accept(ModelWidgetVisitor visitor) throws Exception {
            visitor.visit(this);
        }

        @Override
        public void renderWidgetString(Appendable writer, Map<String, Object> context,
                                       ScreenStringRenderer screenStringRenderer) throws GeneralException {

            // check the condition, if there is one
            boolean condTrue = true;
            if (this.condition != null) {
                if (!this.condition.eval(context)) {
                    condTrue = false;
                }
            }

            // if condition does not exist or evals to true run actions and render widgets, otherwise render fail-widgets
            if (condTrue) {
                // run the actions only if true
                AbstractModelAction.runSubActions(this.actions, context);

                try {
                    // section by definition do not themselves do anything, so this method will generally do nothing, but we'll call it anyway
                    screenStringRenderer.renderSectionBegin(writer, context, this);

                    // render sub-widgets
                    renderSubWidgetsString(this.subWidgets, writer, context, screenStringRenderer);

                    screenStringRenderer.renderSectionEnd(writer, context, this);
                } catch (IOException e) {
                    String errMsg = "Error rendering widgets section [" + getName() + "] in screen named ["
                            + getModelScreen().getName() + "]: " + e.toString();
                    Debug.logError(e, errMsg, MODULE);
                    throw new RuntimeException(errMsg);
                }
            } else {
                try {
                    // section by definition do not themselves do anything, so this method will generally do nothing, but we'll call it anyway
                    screenStringRenderer.renderSectionBegin(writer, context, this);

                    // render sub-widgets
                    renderSubWidgetsString(this.failWidgets, writer, context, screenStringRenderer);

                    screenStringRenderer.renderSectionEnd(writer, context, this);
                } catch (IOException e) {
                    String errMsg = "Error rendering fail-widgets section [" + this.getName() + "] in screen named ["
                            + getModelScreen().getName() + "]: " + e.toString();
                    Debug.logError(e, errMsg, MODULE);
                    throw new RuntimeException(errMsg);
                }
            }

        }

        @Override
        public String getBoundaryCommentName() {
            if (isMainSection) {
                return getModelScreen().getSourceLocation() + "#" + getModelScreen().getName();
            }
            return getName();
        }

        public List<ModelAction> getActions() {
            return actions;
        }

        public List<ModelScreenWidget> getSubWidgets() {
            return subWidgets;
        }

        public List<ModelScreenWidget> getFailWidgets() {
            return failWidgets;
        }

        public boolean isMainSection() {
            return isMainSection;
        }

        public ModelCondition getCondition() {
            return condition;
        }
    }

    public static final class ColumnContainer extends ModelScreenWidget {
        public static final String TAG_NAME = "column-container";
        private final FlexibleStringExpander idExdr;
        private final FlexibleStringExpander styleExdr;
        private final List<Column> columns;

        public ColumnContainer(ModelScreen modelScreen, Element containerElement) {
            super(modelScreen, containerElement);
            this.idExdr = FlexibleStringExpander.getInstance(containerElement.getAttribute("id"));
            this.styleExdr = FlexibleStringExpander.getInstance(containerElement.getAttribute("style"));
            List<? extends Element> subElementList = UtilXml.childElementList(containerElement, "column");
            List<Column> columns = new ArrayList<>(subElementList.size());
            for (Element element : subElementList) {
                columns.add(new Column(modelScreen, element));
            }
            this.columns = Collections.unmodifiableList(columns);
        }

        @Override
        public void accept(ModelWidgetVisitor visitor) throws Exception {
            visitor.visit(this);
        }

        @Override
        public void renderWidgetString(Appendable writer, Map<String, Object> context,
                                       ScreenStringRenderer screenStringRenderer) throws GeneralException, IOException {
            try {
                screenStringRenderer.renderColumnContainer(writer, context, this);
            } catch (IOException e) {
                String errMsg = "Error rendering container in screen named [" + getModelScreen().getName() + "]: " + e.toString();
                Debug.logError(e, errMsg, MODULE);
                throw new RuntimeException(errMsg);
            }
        }

        public List<Column> getColumns() {
            return this.columns;
        }

        public String getId(Map<String, Object> context) {
            return this.idExdr.expandString(context);
        }

        public String getStyle(Map<String, Object> context) {
            return this.styleExdr.expandString(context);
        }

        public FlexibleStringExpander getIdExdr() {
            return idExdr;
        }

        public FlexibleStringExpander getStyleExdr() {
            return styleExdr;
        }
    }

    public static final class Column extends ModelWidget {
        private final FlexibleStringExpander idExdr;
        private final FlexibleStringExpander styleExdr;
        private final List<ModelScreenWidget> subWidgets;

        public Column(ModelScreen modelScreen, Element columnElement) {
            super(columnElement);
            this.idExdr = FlexibleStringExpander.getInstance(columnElement.getAttribute("id"));
            this.styleExdr = FlexibleStringExpander.getInstance(columnElement.getAttribute("style"));
            List<? extends Element> subElementList = UtilXml.childElementList(columnElement);
            this.subWidgets = Collections.unmodifiableList(readSubWidgets(modelScreen, subElementList));
        }

        public List<ModelScreenWidget> getSubWidgets() {
            return this.subWidgets;
        }

        public String getId(Map<String, Object> context) {
            return this.idExdr.expandString(context);
        }

        public String getStyle(Map<String, Object> context) {
            return this.styleExdr.expandString(context);
        }

        @Override
        public void accept(ModelWidgetVisitor visitor) throws Exception {
            visitor.visit(this);
        }

        public FlexibleStringExpander getIdExdr() {
            return idExdr;
        }

        public FlexibleStringExpander getStyleExdr() {
            return styleExdr;
        }
    }

    public static final class Container extends ModelScreenWidget {
        public static final String TAG_NAME = "container";
        private final FlexibleStringExpander idExdr;
        private final FlexibleStringExpander typeExdr;
        private final FlexibleStringExpander styleExdr;
        private final FlexibleStringExpander autoUpdateTargetExdr;
        private final FlexibleStringExpander autoUpdateInterval;
        private final List<ModelScreenWidget> subWidgets;

        public Container(ModelScreen modelScreen, Element containerElement) {
            super(modelScreen, containerElement);
            this.idExdr = FlexibleStringExpander.getInstance(containerElement.getAttribute("id"));
            this.typeExdr = FlexibleStringExpander.getInstance(containerElement.getAttribute("type"));
            this.styleExdr = FlexibleStringExpander.getInstance(containerElement.getAttribute("style"));
            this.autoUpdateTargetExdr = FlexibleStringExpander.getInstance(containerElement.getAttribute("auto-update-target"));
            String autoUpdateInterval = containerElement.getAttribute("auto-update-interval");
            if (autoUpdateInterval.isEmpty()) {
                autoUpdateInterval = "2";
            }
            this.autoUpdateInterval = FlexibleStringExpander.getInstance(autoUpdateInterval);
            // read sub-widgets
            List<? extends Element> subElementList = UtilXml.childElementList(containerElement);
            this.subWidgets = ModelScreenWidget.readSubWidgets(getModelScreen(), subElementList);
        }

        @Override
        public void renderWidgetString(Appendable writer, Map<String, Object> context,
                                       ScreenStringRenderer screenStringRenderer) throws GeneralException, IOException {
            try {
                screenStringRenderer.renderContainerBegin(writer, context, this);

                // render sub-widgets
                renderSubWidgetsString(this.subWidgets, writer, context, screenStringRenderer);

                screenStringRenderer.renderContainerEnd(writer, context, this);
            } catch (IOException e) {
                String errMsg = "Error rendering container in screen named [" + getModelScreen().getName() + "]: " + e.toString();
                Debug.logError(e, errMsg, MODULE);
                throw new RuntimeException(errMsg);
            }
        }

        public String getId(Map<String, Object> context) {
            return this.idExdr.expandString(context);
        }

        public String getType(Map<String, Object> context) {
            return this.typeExdr.expandString(context);
        }

        public String getStyle(Map<String, Object> context) {
            return this.styleExdr.expandString(context);
        }

        public String getAutoUpdateTargetExdr(Map<String, Object> context) {
            return this.autoUpdateTargetExdr.expandString(context);
        }

        public String getAutoUpdateInterval(Map<String, Object> context) {
            return this.autoUpdateInterval.expandString(context);
        }

        public List<ModelScreenWidget> getSubWidgets() {
            return subWidgets;
        }

        @Override
        public void accept(ModelWidgetVisitor visitor) throws Exception {
            visitor.visit(this);
        }

        public FlexibleStringExpander getIdExdr() {
            return idExdr;
        }

        public FlexibleStringExpander getTypeExdr() {
            return typeExdr;
        }

        public FlexibleStringExpander getStyleExdr() {
            return styleExdr;
        }

        public FlexibleStringExpander getAutoUpdateTargetExdr() {
            return autoUpdateTargetExdr;
        }

        public FlexibleStringExpander getAutoUpdateInterval() {
            return autoUpdateInterval;
        }
    }

    public static final class Screenlet extends ModelScreenWidget {
        public static final String TAG_NAME = "screenlet";
        private final FlexibleStringExpander idExdr;
        private final FlexibleStringExpander titleExdr;
        private final Menu navigationMenu;
        private final Menu tabMenu;
        private final Form navigationForm;
        private final boolean collapsible;
        private final FlexibleStringExpander initiallyCollapsed;
        private final boolean saveCollapsed;
        private final boolean padded;
        private final List<ModelScreenWidget> subWidgets;

        public Screenlet(ModelScreen modelScreen, Element screenletElement) {
            super(modelScreen, screenletElement);
            this.idExdr = FlexibleStringExpander.getInstance(screenletElement.getAttribute("id"));
            boolean collapsible = "true".equals(screenletElement.getAttribute("collapsible"));
            this.initiallyCollapsed = FlexibleStringExpander.getInstance(screenletElement.getAttribute("initially-collapsed"));
            if ("true".equals(this.initiallyCollapsed.getOriginal())) {
                collapsible = true;
            }
            this.collapsible = collapsible;
            // By default, for a collapsible screenlet, the collapsed/expanded status must be saved
            this.saveCollapsed = !("false".equals(screenletElement.getAttribute("save-collapsed")));

            boolean padded = !"false".equals(screenletElement.getAttribute("padded"));
            if (this.collapsible && getName().isEmpty() && idExdr.isEmpty()) {
                throw new IllegalArgumentException("Collapsible screenlets must have a name or id [" + getModelScreen().getName() + "]");
            }
            this.titleExdr = FlexibleStringExpander.getInstance(screenletElement.getAttribute("title"));
            List<? extends Element> subElementList = UtilXml.childElementList(screenletElement);
            // Make a copy of the unmodifiable List so we can modify it.
            List<ModelScreenWidget> subWidgets = new ArrayList<>(ModelScreenWidget.readSubWidgets(getModelScreen(), subElementList));
            Menu navigationMenu = null;
            String navMenuName = screenletElement.getAttribute("navigation-menu-name");
            if (!navMenuName.isEmpty()) {
                for (ModelWidget subWidget : subWidgets) {
                    if (navMenuName.equals(subWidget.getName()) && subWidget instanceof Menu) {
                        navigationMenu = (Menu) subWidget;
                        subWidgets.remove(subWidget);
                        break;
                    }
                }
            }
            this.navigationMenu = navigationMenu;
            Menu tabMenu = null;
            String tabMenuName = screenletElement.getAttribute("tab-menu-name");
            if (!tabMenuName.isEmpty()) {
                for (ModelWidget subWidget : subWidgets) {
                    if (tabMenuName.equals(subWidget.getName()) && subWidget instanceof Menu) {
                        tabMenu = (Menu) subWidget;
                        subWidgets.remove(subWidget);
                        break;
                    }
                }
            }
            this.tabMenu = tabMenu;
            Form navigationForm = null;
            String formName = screenletElement.getAttribute("navigation-form-name");
            if (!formName.isEmpty() && this.navigationMenu == null) {
                for (ModelWidget subWidget : subWidgets) {
                    if (formName.equals(subWidget.getName()) && subWidget instanceof Form) {
                        navigationForm = (Form) subWidget;
                        padded = false;
                        break;
                    }
                }
            }
            this.subWidgets = Collections.unmodifiableList(subWidgets);
            this.navigationForm = navigationForm;
            this.padded = padded;
        }

        @Override
        public void renderWidgetString(Appendable writer, Map<String, Object> context,
                                       ScreenStringRenderer screenStringRenderer) throws GeneralException, IOException {
            boolean collapsed = getInitiallyCollapsed(context);
            if (this.collapsible) {
                String preferenceKey = getPreferenceKey(context) + "_collapsed";
                Map<String, Object> requestParameters = UtilGenerics.cast(context.get("requestParameters"));
                if (requestParameters != null) {
                    String collapsedParam = (String) requestParameters.get(preferenceKey);
                    if (collapsedParam != null) {
                        collapsed = "true".equals(collapsedParam);
                    }
                }
            }
            try {
                screenStringRenderer.renderScreenletBegin(writer, context, collapsed, this);
                for (ModelScreenWidget subWidget : this.subWidgets) {
                    screenStringRenderer.renderScreenletSubWidget(writer, context, subWidget, this);
                }
                screenStringRenderer.renderScreenletEnd(writer, context, this);
            } catch (IOException e) {
                String errMsg = "Error rendering screenlet in screen named [" + getModelScreen().getName() + "]: ";
                Debug.logError(e, errMsg, MODULE);
                throw new RuntimeException(errMsg + e);
            }
        }

        public boolean collapsible() {
            return this.collapsible;
        }

        //initially-collapsed status, which may be overriden by user preference
        public boolean getInitiallyCollapsed(Map<String, Object> context) {
            String screenletId = this.getId(context) + "_collapsed";
            Map<String, ? extends Object> userPreferences = UtilGenerics.cast(context.get("userPreferences"));
            if (userPreferences != null && userPreferences.containsKey(screenletId)) {
                return Boolean.valueOf((String) userPreferences.get(screenletId));
            }

            return "true".equals(this.initiallyCollapsed.expand(context));
        }

        public boolean saveCollapsed() {
            return this.saveCollapsed;
        }
        public boolean padded() {
            return this.padded;
        }

        public String getPreferenceKey(Map<String, Object> context) {
            String name = this.idExdr.expandString(context);
            if (name.isEmpty()) {
                name = "screenlet" + "_" + Integer.toHexString(hashCode());
            }
            return name;
        }

        public String getId(Map<String, Object> context) {
            return this.idExdr.expandString(context);
        }

        public List<ModelScreenWidget> getSubWidgets() {
            return subWidgets;
        }

        public String getTitle(Map<String, Object> context) {
            String title = this.titleExdr.expandString(context);
            UtilCodec.SimpleEncoder simpleEncoder = (UtilCodec.SimpleEncoder) context.get("simpleEncoder");
            if (simpleEncoder != null) {
                title = simpleEncoder.encode(title);
            }
            return title;
        }

        public Menu getNavigationMenu() {
            return this.navigationMenu;
        }

        public Form getNavigationForm() {
            return this.navigationForm;
        }

        public Menu getTabMenu() {
            return this.tabMenu;
        }

        @Override
        public void accept(ModelWidgetVisitor visitor) throws Exception {
            visitor.visit(this);
        }

        public FlexibleStringExpander getIdExdr() {
            return idExdr;
        }

        public FlexibleStringExpander getTitleExdr() {
            return titleExdr;
        }

        public boolean getCollapsible() {
            return collapsible;
        }

        public FlexibleStringExpander getInitiallyCollapsed() {
            return initiallyCollapsed;
        }

        public boolean getSaveCollapsed() {
            return saveCollapsed;
        }

        public boolean getPadded() {
            return padded;
        }
    }

    public static final class HorizontalSeparator extends ModelScreenWidget {
        public static final String TAG_NAME = "horizontal-separator";
        private final FlexibleStringExpander idExdr;
        private final FlexibleStringExpander styleExdr;

        public HorizontalSeparator(ModelScreen modelScreen, Element separatorElement) {
            super(modelScreen, separatorElement);
            this.idExdr = FlexibleStringExpander.getInstance(separatorElement.getAttribute("id"));
            this.styleExdr = FlexibleStringExpander.getInstance(separatorElement.getAttribute("style"));
        }

        @Override
        public void renderWidgetString(Appendable writer, Map<String, Object> context,
                                       ScreenStringRenderer screenStringRenderer) throws GeneralException, IOException {
            screenStringRenderer.renderHorizontalSeparator(writer, context, this);
        }

        public String getId(Map<String, Object> context) {
            return this.idExdr.expandString(context);
        }

        public String getStyle(Map<String, Object> context) {
            return this.styleExdr.expandString(context);
        }

        @Override
        public void accept(ModelWidgetVisitor visitor) throws Exception {
            visitor.visit(this);
        }

        public FlexibleStringExpander getIdExdr() {
            return idExdr;
        }

        public FlexibleStringExpander getStyleExdr() {
            return styleExdr;
        }
    }

    public static final class IncludeScreen extends ModelScreenWidget {
        public static final String TAG_NAME = "include-screen";
        private final FlexibleStringExpander nameExdr;
        private final FlexibleStringExpander locationExdr;
        private final FlexibleStringExpander shareScopeExdr;

        public IncludeScreen(ModelScreen modelScreen, Element includeScreenElement) {
            super(modelScreen, includeScreenElement);
            this.nameExdr = FlexibleStringExpander.getInstance(includeScreenElement.getAttribute("name"));
            this.locationExdr = FlexibleStringExpander.getInstance(includeScreenElement.getAttribute("location"));
            this.shareScopeExdr = FlexibleStringExpander.getInstance(includeScreenElement.getAttribute("share-scope"));
        }

        @Override
        public void renderWidgetString(Appendable writer, Map<String, Object> context,
                                       ScreenStringRenderer screenStringRenderer) throws GeneralException, IOException {
            // if we are not sharing the scope, protect it using the MapStack
            boolean protectScope = !shareScope(context);
            if (protectScope) {
                if (!(context instanceof MapStack<?>)) {
                    context = MapStack.create(context);
                }

                UtilGenerics.<MapStack<String>>cast(context).push();
                Object obj = context.get("_WIDGETTRAIL_");

                // build the widgetpath
                List<String> widgetTrail = (obj instanceof List) ? UtilGenerics.cast(obj) : null;
                if (widgetTrail == null) {
                    widgetTrail = new LinkedList<>();
                }

                String thisName = nameExdr.expandString(context);
                widgetTrail.add(thisName);
                context.put("_WIDGETTRAIL_", widgetTrail);
            }

            // don't need the renderer here, will just pass this on down to another screen call;
            // screenStringRenderer.renderContainerBegin(writer, context, this);
            String name = this.getName(context);
            String location = this.getLocation(context);

            if (name.isEmpty()) {
                if (Debug.verboseOn()) {
                    Debug.logVerbose("In the include-screen tag the screen name was empty, ignoring include; in screen ["
                            + getModelScreen().getName() + "]", MODULE);
                }
                return;
            }

            ScreenFactory.renderReferencedScreen(name, location, this, writer, context, screenStringRenderer);

            if (protectScope) {
                UtilGenerics.<MapStack<String>>cast(context).pop();
            }
        }

        public String getName(Map<String, Object> context) {
            return this.nameExdr.expandString(context);
        }

        public String getLocation(Map<String, Object> context) {
            return this.locationExdr.expandString(context);
        }

        public boolean shareScope(Map<String, Object> context) {
            String shareScopeString = this.shareScopeExdr.expandString(context);
            // defaults to false, so anything but true is false
            return "true".equals(shareScopeString);
        }

        @Override
        public void accept(ModelWidgetVisitor visitor) throws Exception {
            visitor.visit(this);
        }

        public FlexibleStringExpander getNameExdr() {
            return nameExdr;
        }

        public FlexibleStringExpander getLocationExdr() {
            return locationExdr;
        }

        public FlexibleStringExpander getShareScopeExdr() {
            return shareScopeExdr;
        }
    }

    public static final class DecoratorScreen extends ModelScreenWidget {
        public static final String TAG_NAME = "decorator-screen";
        private final FlexibleStringExpander nameExdr;
        private final FlexibleStringExpander locationExdr;
        private final Map<String, ModelScreenWidget> sectionMap;

        public DecoratorScreen(ModelScreen modelScreen, Element decoratorScreenElement) {
            super(modelScreen, decoratorScreenElement);
            this.nameExdr = FlexibleStringExpander.getInstance(decoratorScreenElement.getAttribute("name"));
            this.locationExdr = FlexibleStringExpander.getInstance(decoratorScreenElement.getAttribute("location"));
            Map<String, ModelScreenWidget> sectionMap = new HashMap<>();
            List<? extends Element> decoratorSectionElementList = UtilXml.childElementList(decoratorScreenElement, "decorator-section");
            for (Element decoratorSectionElement: decoratorSectionElementList) {
                DecoratorSection decoratorSection = new DecoratorSection(modelScreen, decoratorSectionElement);
                sectionMap.put(decoratorSection.getName(), decoratorSection);
            }
            this.sectionMap = Collections.unmodifiableMap(sectionMap);
        }

        @Override
        public void renderWidgetString(Appendable writer, Map<String, Object> context,
                                       ScreenStringRenderer screenStringRenderer) throws GeneralException, IOException {
            // isolate the scope
            if (!(context instanceof MapStack)) {
                context = MapStack.create(context);
            }

            MapStack<String> contextMs = UtilGenerics.cast(context);

            // create a standAloneStack, basically a "save point" for this SectionsRenderer,
            // and make a new "screens" object just for it so it is isolated and doesn't follow the stack down
            MapStack<String> standAloneStack = contextMs.standAloneChildStack();
            standAloneStack.put("screens", new ScreenRenderer(writer, standAloneStack, screenStringRenderer));
            SectionsRenderer sections = new SectionsRenderer(this.sectionMap, standAloneStack, writer, screenStringRenderer);

            // put the sectionMap in the context, make sure it is in the sub-scope, ie after calling push on the MapStack
            contextMs.push();
            context.put("sections", sections);

            String name = this.getName(context);
            String location = this.getLocation(context);

            ScreenFactory.renderReferencedScreen(name, location, this, writer, context, screenStringRenderer);

            contextMs.pop();
        }

        public String getName(Map<String, Object> context) {
            return this.nameExdr.expandString(context);
        }

        public String getLocation(Map<String, Object> context) {
            return this.locationExdr.expandString(context);
        }

        public Map<String, ModelScreenWidget> getSectionMap() {
            return sectionMap;
        }

        @Override
        public void accept(ModelWidgetVisitor visitor) throws Exception {
            visitor.visit(this);
        }

        public FlexibleStringExpander getNameExdr() {
            return nameExdr;
        }

        public FlexibleStringExpander getLocationExdr() {
            return locationExdr;
        }

    }

    public static final class DecoratorSection extends ModelScreenWidget {
        public static final String TAG_NAME = "decorator-section";
        private final List<ModelScreenWidget> subWidgets;

        public DecoratorSection(ModelScreen modelScreen, Element decoratorSectionElement) {
            super(modelScreen, decoratorSectionElement);
            // read sub-widgets
            List<? extends Element> subElementList = UtilXml.childElementList(decoratorSectionElement);
            this.subWidgets = ModelScreenWidget.readSubWidgets(getModelScreen(), subElementList);
        }

        @Override
        public void renderWidgetString(Appendable writer, Map<String, Object> context,
                                       ScreenStringRenderer screenStringRenderer) throws GeneralException, IOException {
            // render sub-widgets
            renderSubWidgetsString(this.subWidgets, writer, context, screenStringRenderer);
        }

        public List<ModelScreenWidget> getSubWidgets() {
            return subWidgets;
        }

        @Override
        public void accept(ModelWidgetVisitor visitor) throws Exception {
            visitor.visit(this);
        }
    }

    public static final class DecoratorSectionInclude extends ModelScreenWidget {
        public static final String TAG_NAME = "decorator-section-include";

        public DecoratorSectionInclude(ModelScreen modelScreen, Element decoratorSectionElement) {
            super(modelScreen, decoratorSectionElement);
        }

        @Override
        public void renderWidgetString(Appendable writer, Map<String, Object> context,
                                       ScreenStringRenderer screenStringRenderer) throws GeneralException, IOException {
            Map<String, ? extends Object> preRenderedContent = UtilGenerics.cast(context.get("preRenderedContent"));
            if (preRenderedContent != null && preRenderedContent.containsKey(getName())) {
                try {
                    writer.append((String) preRenderedContent.get(getName()));
                } catch (IOException e) {
                    String errMsg = "Error rendering pre-rendered content in screen named [" + getModelScreen().getName() + "]: " + e.toString();
                    Debug.logError(e, errMsg, MODULE);
                    throw new RuntimeException(errMsg);
                }
            } else {
                SectionsRenderer sections = (SectionsRenderer) context.get("sections");
                // for now if sections is null, just log a warning; may be permissible to make the screen for flexible
                if (sections == null) {
                    Debug.logWarning("In decorator-section-include could not find sections object in the context, "
                            + "not rendering section with name [" + getName() + "]", MODULE);
                } else {
                    sections.render(getName());
                }
            }
        }

        @Override
        public void accept(ModelWidgetVisitor visitor) throws Exception {
            visitor.visit(this);
        }
    }

    public static final class Label extends ModelScreenWidget {
        public static final String TAG_NAME = "label";
        private final FlexibleStringExpander textExdr;
        private final FlexibleStringExpander idExdr;
        private final FlexibleStringExpander styleExdr;

        public Label(ModelScreen modelScreen, Element labelElement) {
            super(modelScreen, labelElement);

            // put the text attribute first, then the pcdata under the element, if both are there of course
            String textAttr = labelElement.getAttribute("text");
            String pcdata = UtilXml.elementValue(labelElement);
            if (pcdata == null) {
                pcdata = "";
            }
            this.textExdr = FlexibleStringExpander.getInstance(textAttr + pcdata);

            this.idExdr = FlexibleStringExpander.getInstance(labelElement.getAttribute("id"));
            this.styleExdr = FlexibleStringExpander.getInstance(labelElement.getAttribute("style"));
        }

        @Override
        public void renderWidgetString(Appendable writer, Map<String, Object> context, ScreenStringRenderer screenStringRenderer) {
            try {
                screenStringRenderer.renderLabel(writer, context, this);
            } catch (IOException e) {
                String errMsg = "Error rendering label in screen named [" + getModelScreen().getName() + "]: " + e.toString();
                Debug.logError(e, errMsg, MODULE);
                throw new RuntimeException(errMsg);
            }
        }

        public String getText(Map<String, Object> context) {
            String text = this.textExdr.expandString(context);
            // FIXME: Encoding should be done by the renderer, not by the model.
            UtilCodec.SimpleEncoder simpleEncoder = (UtilCodec.SimpleEncoder) context.get("simpleEncoder");
            if (simpleEncoder != null) {
                text = simpleEncoder.encode(text);
            }
            return text;
        }

        public String getId(Map<String, Object> context) {
            return this.idExdr.expandString(context);
        }

        public String getStyle(Map<String, Object> context) {
            return this.styleExdr.expandString(context);
        }

        @Override
        public void accept(ModelWidgetVisitor visitor) throws Exception {
            visitor.visit(this);
        }

        public FlexibleStringExpander getTextExdr() {
            return textExdr;
        }

        public FlexibleStringExpander getIdExdr() {
            return idExdr;
        }

        public FlexibleStringExpander getStyleExdr() {
            return styleExdr;
        }
    }

    public static final class Form extends ModelScreenWidget {
        public static final String TAG_NAME = "include-form";
        private final FlexibleStringExpander nameExdr;
        private final FlexibleStringExpander locationExdr;
        private final FlexibleStringExpander shareScopeExdr;

        public Form(ModelScreen modelScreen, Element formElement) {
            super(modelScreen, formElement);
            this.nameExdr = FlexibleStringExpander.getInstance(formElement.getAttribute("name"));
            this.locationExdr = FlexibleStringExpander.getInstance(formElement.getAttribute("location"));
            this.shareScopeExdr = FlexibleStringExpander.getInstance(formElement.getAttribute("share-scope"));
        }

        @Override
        public void renderWidgetString(Appendable writer, Map<String, Object> context, ScreenStringRenderer screenStringRenderer) {
            // Output format might not support forms, so make form rendering optional.
            FormStringRenderer formStringRenderer = (FormStringRenderer) context.get("formStringRenderer");
            if (formStringRenderer == null) {
                if (Debug.verboseOn()) {
                    Debug.logVerbose("FormStringRenderer instance not found in rendering context, form not rendered.", MODULE);
                }
                return;
            }
            boolean protectScope = !shareScope(context);
            if (protectScope) {
                if (!(context instanceof MapStack<?>)) {
                    context = MapStack.create(context);
                }
                UtilGenerics.<MapStack<String>>cast(context).push();
            }
            try {
                ModelForm modelForm = getModelForm(context);
                FormRenderer renderer = new FormRenderer(modelForm, formStringRenderer);
                renderer.render(writer, context);
            } catch (Exception e) {
                String errMsg = "Error rendering included form named [" + getName() + "] at location ["
                        + this.getLocation(context) + "]: " + e.toString();
                Debug.logError(e, errMsg, MODULE);
                throw new RuntimeException(errMsg + e);
            }

            if (protectScope) {
                UtilGenerics.<MapStack<String>>cast(context).pop();
            }
        }

        public ModelForm getModelForm(Map<String, Object> context) throws IOException, SAXException, ParserConfigurationException {
            String name = this.getName(context);
            String location = this.getLocation(context);
            VisualTheme visualTheme = (VisualTheme) context.get("visualTheme");
            return FormFactory.getFormFromLocation(location, name, getModelScreen().getDelegator(context).getModelReader(),
                    visualTheme, getModelScreen().getDispatcher(context).getDispatchContext());
        }

        public String getName(Map<String, Object> context) {
            return this.nameExdr.expandString(context);
        }

        public String getLocation() {
            return locationExdr.getOriginal();
        }

        public String getLocation(Map<String, Object> context) {
            return this.locationExdr.expandString(context);
        }

        public boolean shareScope(Map<String, Object> context) {
            String shareScopeString = this.shareScopeExdr.expandString(context);
            // defaults to false, so anything but true is false
            return "true".equals(shareScopeString);
        }

        @Override
        public void accept(ModelWidgetVisitor visitor) throws Exception {
            visitor.visit(this);
        }

        public FlexibleStringExpander getNameExdr() {
            return nameExdr;
        }

        public FlexibleStringExpander getLocationExdr() {
            return locationExdr;
        }

        public FlexibleStringExpander getShareScopeExdr() {
            return shareScopeExdr;
        }
    }

    public static final class Grid extends ModelScreenWidget {
        public static final String TAG_NAME = "include-grid";
        private final FlexibleStringExpander nameExdr;
        private final FlexibleStringExpander locationExdr;
        private final FlexibleStringExpander shareScopeExdr;

        public Grid(ModelScreen modelScreen, Element formElement) {
            super(modelScreen, formElement);
            this.nameExdr = FlexibleStringExpander.getInstance(formElement.getAttribute("name"));
            this.locationExdr = FlexibleStringExpander.getInstance(formElement.getAttribute("location"));
            this.shareScopeExdr = FlexibleStringExpander.getInstance(formElement.getAttribute("share-scope"));
        }

        @Override
        public void renderWidgetString(Appendable writer, Map<String, Object> context, ScreenStringRenderer screenStringRenderer) {
            // Output format might not support forms, so make form rendering optional.
            FormStringRenderer formStringRenderer = (FormStringRenderer) context.get("formStringRenderer");
            if (formStringRenderer == null) {
                if (Debug.verboseOn()) {
                    Debug.logVerbose("FormStringRenderer instance not found in rendering context, form not rendered.", MODULE);
                }
                return;
            }
            boolean protectScope = !shareScope(context);
            if (protectScope) {
                if (!(context instanceof MapStack<?>)) {
                    context = MapStack.create(context);
                }
                UtilGenerics.<MapStack<String>>cast(context).push();
            }
            ModelForm modelForm = getModelForm(context);
            FormRenderer renderer = new FormRenderer(modelForm, formStringRenderer);
            try {
                renderer.render(writer, context);
            } catch (Exception e) {
                String errMsg = "Error rendering included grid named [" + getName() + "] at location ["
                        + this.getLocation(context) + "]: " + e.toString();
                Debug.logError(e, errMsg, MODULE);
                throw new RuntimeException(errMsg + e);
            }
            if (protectScope) {
                UtilGenerics.<MapStack<String>>cast(context).pop();
            }
        }

        public ModelForm getModelForm(Map<String, Object> context) {
            ModelForm modelForm = null;
            String name = this.getName(context);
            String location = this.getLocation(context);
            try {
                VisualTheme visualTheme = (VisualTheme) context.get("visualTheme");
                modelForm = GridFactory.getGridFromLocation(location, name, getModelScreen().getDelegator(context).getModelReader(),
                        visualTheme, getModelScreen().getDispatcher(context).getDispatchContext());
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                String errMsg = "Error rendering included form named [" + name + "] at location [" + location + "]: ";
                Debug.logError(e, errMsg, MODULE);
                throw new RuntimeException(errMsg + e);
            }
            return modelForm;
        }

        public String getName(Map<String, Object> context) {
            return this.nameExdr.expandString(context);
        }

        public String getLocation() {
            return locationExdr.getOriginal();
        }

        public String getLocation(Map<String, Object> context) {
            return this.locationExdr.expandString(context);
        }

        public boolean shareScope(Map<String, Object> context) {
            String shareScopeString = this.shareScopeExdr.expandString(context);
            // defaults to false, so anything but true is false
            return "true".equals(shareScopeString);
        }

        @Override
        public void accept(ModelWidgetVisitor visitor) throws Exception {
            visitor.visit(this);
        }

        public FlexibleStringExpander getNameExdr() {
            return nameExdr;
        }

        public FlexibleStringExpander getLocationExdr() {
            return locationExdr;
        }

        public FlexibleStringExpander getShareScopeExdr() {
            return shareScopeExdr;
        }
    }

    public static final class Tree extends ModelScreenWidget {
        public static final String TAG_NAME = "include-tree";
        private final FlexibleStringExpander nameExdr;
        private final FlexibleStringExpander locationExdr;
        private final FlexibleStringExpander shareScopeExdr;

        public Tree(ModelScreen modelScreen, Element treeElement) {
            super(modelScreen, treeElement);
            this.nameExdr = FlexibleStringExpander.getInstance(treeElement.getAttribute("name"));
            this.locationExdr = FlexibleStringExpander.getInstance(treeElement.getAttribute("location"));
            this.shareScopeExdr = FlexibleStringExpander.getInstance(treeElement.getAttribute("share-scope"));
        }

        @Override
        public void renderWidgetString(Appendable writer, Map<String, Object> context,
                                       ScreenStringRenderer screenStringRenderer) throws GeneralException, IOException {
            // Output format might not support trees, so make tree rendering optional.
            TreeStringRenderer treeStringRenderer = (TreeStringRenderer) context.get("treeStringRenderer");
            if (treeStringRenderer == null) {
                if (Debug.verboseOn()) {
                    Debug.logVerbose("TreeStringRenderer instance not found in rendering context, tree not rendered.", MODULE);
                }
                return;
            }
            boolean protectScope = !shareScope(context);
            if (protectScope) {
                if (!(context instanceof MapStack<?>)) {
                    context = MapStack.create(context);
                }
                UtilGenerics.<MapStack<String>>cast(context).push();
            }

            String name = this.getName(context);
            String location = this.getLocation(context);
            ModelTree modelTree = null;
            try {
                modelTree = TreeFactory.getTreeFromLocation(this.getLocation(context), this.getName(context),
                        getModelScreen().getDelegator(context), getModelScreen().getDispatcher(context));
            } catch (IOException | SAXException | ParserConfigurationException e) {
                String errMsg = "Error rendering included tree named [" + name + "] at location [" + location + "]: " + e.toString();
                Debug.logError(e, errMsg, MODULE);
                throw new RuntimeException(errMsg);
            }
            modelTree.renderTreeString(writer, context, treeStringRenderer);
            if (protectScope) {
                UtilGenerics.<MapStack<String>>cast(context).pop();
            }
        }

        public String getName(Map<String, Object> context) {
            return this.nameExdr.expandString(context);
        }

        public String getLocation(Map<String, Object> context) {
            return this.locationExdr.expandString(context);
        }

        public boolean shareScope(Map<String, Object> context) {
            String shareScopeString = this.shareScopeExdr.expandString(context);
            // defaults to false, so anything but true is false
            return "true".equals(shareScopeString);
        }

        @Override
        public void accept(ModelWidgetVisitor visitor) throws Exception {
            visitor.visit(this);
        }

        public FlexibleStringExpander getLocationExdr() {
            return locationExdr;
        }

        public FlexibleStringExpander getShareScopeExdr() {
            return shareScopeExdr;
        }
    }

    public static final class PlatformSpecific extends ModelScreenWidget {
        private static final List<String> PLATEFORM_SPECIFIC_SUPPORT_RENDERING_TYPE = UtilMisc.toList("html", "xsl-fo", "xml", "text", "csv", "xls");
        public static final String TAG_NAME = "platform-specific";
        private final Map<String, ModelScreenWidget> subWidgets;

        public PlatformSpecific(ModelScreen modelScreen, Element platformSpecificElement) {
            super(modelScreen, platformSpecificElement);
            Map<String, ModelScreenWidget> subWidgets = new HashMap<>();
            List<? extends Element> childElements = UtilXml.childElementList(platformSpecificElement);
            if (childElements != null) {
                for (Element childElement: childElements) {
                    String renderingType = childElement.getNodeName();

                    // Remove the namespace if is present
                    if (renderingType.contains(":")) {
                        renderingType = StringUtil.split(renderingType, ":").get(1);
                    }
                    if (PLATEFORM_SPECIFIC_SUPPORT_RENDERING_TYPE.contains(renderingType)) {
                        subWidgets.put(renderingType, new HtmlWidget(modelScreen, childElement));
                    } else {
                        throw new IllegalArgumentException("Tag not supported under the platform-specific tag with name: "
                                + childElement.getNodeName());
                    }
                }
            }
            this.subWidgets = Collections.unmodifiableMap(subWidgets);
        }

        @Override
        public void renderWidgetString(Appendable writer, Map<String, Object> context,
                                       ScreenStringRenderer screenStringRenderer) throws GeneralException, IOException {
            ModelScreenWidget subWidget = null;
            subWidget = subWidgets.get(screenStringRenderer.getRendererName());
            if (subWidget == null) {
                // This is here for backward compatibility
                Debug.logWarning("In platform-dependent could not find template for "
                        + screenStringRenderer.getRendererName() + ", using the one for html.", MODULE);
                subWidget = subWidgets.get("html");
            }
            if (subWidget != null) {
                subWidget.renderWidgetString(writer, context, screenStringRenderer);
            }
        }

        @Override
        public void accept(ModelWidgetVisitor visitor) throws Exception {
            visitor.visit(this);
        }

        public Map<String, ModelScreenWidget> getSubWidgets() {
            return subWidgets;
        }
    }

    public static final class Content extends ModelScreenWidget {
        public static final String TAG_NAME = "content";

        private final FlexibleStringExpander contentId;
        private final FlexibleStringExpander editRequest;
        private final FlexibleStringExpander editContainerStyle;
        private final FlexibleStringExpander enableEditName;
        private final boolean xmlEscape;
        private final FlexibleStringExpander dataResourceId;
        private final String width;
        private final String height;
        private final String border;

        public Content(ModelScreen modelScreen, Element subContentElement) {
            super(modelScreen, subContentElement);
            this.contentId = FlexibleStringExpander.getInstance(subContentElement.getAttribute("content-id"));
            this.dataResourceId = FlexibleStringExpander.getInstance(subContentElement.getAttribute("dataresource-id"));
            this.editRequest = FlexibleStringExpander.getInstance(subContentElement.getAttribute("edit-request"));
            this.editContainerStyle = FlexibleStringExpander.getInstance(subContentElement.getAttribute("edit-container-style"));
            this.enableEditName = FlexibleStringExpander.getInstance(subContentElement.getAttribute("enable-edit-name"));
            this.xmlEscape = "true".equals(subContentElement.getAttribute("xml-escape"));
            String width = subContentElement.getAttribute("width");
            if (width.isEmpty()) {
                width = "60%";
            }
            this.height = subContentElement.getAttribute("height");
            if (this.height.isEmpty()) {
                width = "400px";
            }
            this.width = width;
            this.border = subContentElement.getAttribute("border");
        }

        @Override
        public void renderWidgetString(Appendable writer, Map<String, Object> context, ScreenStringRenderer screenStringRenderer) {
            try {
                // pushing the contentId on the context as "contentId" is done
                // because many times there will be embedded "subcontent" elements
                // that use the syntax: <subcontent content-id="${contentId}"...
                // and this is a step to make sure that it is there.
                Delegator delegator = (Delegator) context.get("delegator");
                GenericValue content = null;
                String expandedDataResourceId = getDataResourceId(context);
                String expandedContentId = getContentId(context);
                if (!(context instanceof MapStack<?>)) {
                    context = MapStack.create(context);
                }

                // This is an important step to make sure that the current contentId is in the context
                // as templates that contain "subcontent" elements will expect to find the master
                // contentId in the context as "contentId".
                UtilGenerics.<MapStack<String>>cast(context).push();
                context.put("contentId", expandedContentId);

                if (expandedDataResourceId.isEmpty()) {
                    if (!expandedContentId.isEmpty()) {
                        content = EntityQuery.use(delegator).from("Content").where("contentId", expandedContentId).cache().queryOne();
                    } else {
                        String errMsg = "contentId is empty.";
                        Debug.logError(errMsg, MODULE);
                        return;
                    }
                    if (content != null) {
                        if (content.get("dataResourceId") != null) {
                            expandedDataResourceId = content.getString("dataResourceId");
                        }
                    } else {
                        String errMsg = "Could not find content with contentId [" + expandedContentId + "] ";
                        Debug.logError(errMsg, MODULE);
                        throw new RuntimeException(errMsg);
                    }
                }

                GenericValue dataResource = null;
                if (!expandedDataResourceId.isEmpty()) {
                    dataResource = EntityQuery.use(delegator).from("DataResource").where("dataResourceId", expandedDataResourceId).cache().queryOne();
                }

                String mimeTypeId = null;
                if (dataResource != null) {
                    mimeTypeId = dataResource.getString("mimeTypeId");
                }
                if (content != null) {
                    mimeTypeId = content.getString("mimeTypeId");
                }

                // This is to render an image only, not an application document
                if (!(mimeTypeId != null && mimeTypeId.indexOf("application") >= 0)) {
                    screenStringRenderer.renderContentBegin(writer, context, this);
                    screenStringRenderer.renderContentBody(writer, context, this);
                    screenStringRenderer.renderContentEnd(writer, context, this);
                }
                UtilGenerics.<MapStack<String>>cast(context).pop();
            } catch (IOException | GenericEntityException e) {
                String errMsg = "Error rendering content with contentId [" + getContentId(context) + "]: " + e.toString();
                Debug.logError(e, errMsg, MODULE);
                throw new RuntimeException(errMsg);
            }
        }

        public String getContentId(Map<String, Object> context) {
            return this.contentId.expandString(context);
        }

        public String getDataResourceId() {
            return this.dataResourceId.getOriginal();
        }

        public String getDataResourceId(Map<String, Object> context) {
            return this.dataResourceId.expandString(context);
        }

        public String getEditRequest(Map<String, Object> context) {
            return this.editRequest.expandString(context);
        }

        public String getEditContainerStyle(Map<String, Object> context) {
            return this.editContainerStyle.expandString(context);
        }

        public String getEnableEditName(Map<String, Object> context) {
            return this.enableEditName.expandString(context);
        }

        public boolean xmlEscape() {
            return this.xmlEscape;
        }

        public String getWidth() {
            return this.width;
        }

        public String getHeight() {
            return this.height;
        }

        public String getBorder() {
            return this.border;
        }

        @Override
        public void accept(ModelWidgetVisitor visitor) throws Exception {
            visitor.visit(this);
        }

        public FlexibleStringExpander getContentId() {
            return contentId;
        }

        public FlexibleStringExpander getEditRequest() {
            return editRequest;
        }

        public FlexibleStringExpander getEditContainerStyle() {
            return editContainerStyle;
        }

        public FlexibleStringExpander getEnableEditName() {
            return enableEditName;
        }
    }

    public static final class SubContent extends ModelScreenWidget {
        public static final String TAG_NAME = "sub-content";
        private final FlexibleStringExpander contentId;
        private final FlexibleStringExpander mapKey;
        private final FlexibleStringExpander editRequest;
        private final FlexibleStringExpander editContainerStyle;
        private final FlexibleStringExpander enableEditName;
        private final boolean xmlEscape;

        public SubContent(ModelScreen modelScreen, Element subContentElement) {
            super(modelScreen, subContentElement);
            this.contentId = FlexibleStringExpander.getInstance(subContentElement.getAttribute("content-id"));
            String mapKey = subContentElement.getAttribute("map-key");
            if (mapKey.isEmpty()) {
                mapKey = subContentElement.getAttribute("assoc-name");
            }
            this.mapKey = FlexibleStringExpander.getInstance(mapKey);
            this.editRequest = FlexibleStringExpander.getInstance(subContentElement.getAttribute("edit-request"));
            this.editContainerStyle = FlexibleStringExpander.getInstance(subContentElement.getAttribute("edit-container-style"));
            this.enableEditName = FlexibleStringExpander.getInstance(subContentElement.getAttribute("enable-edit-name"));
            this.xmlEscape = "true".equals(subContentElement.getAttribute("xml-escape"));
        }

        @Override
        public void renderWidgetString(Appendable writer, Map<String, Object> context, ScreenStringRenderer screenStringRenderer) {
            try {
                screenStringRenderer.renderSubContentBegin(writer, context, this);
                screenStringRenderer.renderSubContentBody(writer, context, this);
                screenStringRenderer.renderSubContentEnd(writer, context, this);
            } catch (IOException e) {
                String errMsg = "Error rendering subContent with contentId [" + getContentId(context) + "]: " + e.toString();
                Debug.logError(e, errMsg, MODULE);
                throw new RuntimeException(errMsg);
            }
        }

        public String getContentId(Map<String, Object> context) {
            return this.contentId.expandString(context);
        }

        public String getMapKey(Map<String, Object> context) {
            return this.mapKey.expandString(context);
        }

        public String getEditRequest(Map<String, Object> context) {
            return this.editRequest.expandString(context);
        }

        public String getEditContainerStyle(Map<String, Object> context) {
            return this.editContainerStyle.expandString(context);
        }

        public String getEnableEditName(Map<String, Object> context) {
            return this.enableEditName.expandString(context);
        }

        public boolean xmlEscape() {
            return this.xmlEscape;
        }

        @Override
        public void accept(ModelWidgetVisitor visitor) throws Exception {
            // TODO Auto-generated method stub

        }
    }

    public static final class Menu extends ModelScreenWidget {
        public static final String TAG_NAME = "include-menu";
        private final FlexibleStringExpander nameExdr;
        private final FlexibleStringExpander locationExdr;

        public Menu(ModelScreen modelScreen, Element menuElement) {
            super(modelScreen, menuElement);
            this.nameExdr = FlexibleStringExpander.getInstance(menuElement.getAttribute("name"));
            this.locationExdr = FlexibleStringExpander.getInstance(menuElement.getAttribute("location"));
        }

        @Override
        public void renderWidgetString(Appendable writer, Map<String, Object> context, ScreenStringRenderer screenStringRenderer) throws IOException {
            // Output format might not support menus, so make menu rendering optional.
            MenuStringRenderer menuStringRenderer = (MenuStringRenderer) context.get("menuStringRenderer");
            if (menuStringRenderer == null) {
                if (Debug.verboseOn()) {
                    Debug.logVerbose("MenuStringRenderer instance not found in rendering context, menu not rendered.", MODULE);
                }
                return;
            }
            ModelMenu modelMenu = getModelMenu(context);
            modelMenu.renderMenuString(writer, context, menuStringRenderer);
        }

        public ModelMenu getModelMenu(Map<String, Object> context) {
            String name = this.getName(context);
            String location = this.getLocation(context);
            ModelMenu modelMenu = null;
            try {
                modelMenu = MenuFactory.getMenuFromLocation(location, name, (VisualTheme) context.get("visualTheme"));
            } catch (Exception e) {
                String errMsg = "Error rendering included menu named [" + name + "] at location [" + location + "]: ";
                Debug.logError(e, errMsg, MODULE);
                throw new RuntimeException(errMsg + e);
            }
            return modelMenu;
        }

        public String getName(Map<String, Object> context) {
            return this.nameExdr.expandString(context);
        }

        public String getLocation(Map<String, Object> context) {
            return this.locationExdr.expandString(context);
        }

        @Override
        public void accept(ModelWidgetVisitor visitor) throws Exception {
            visitor.visit(this);
        }

        public FlexibleStringExpander getLocationExdr() {
            return locationExdr;
        }
    }

    public static final class ScreenLink extends ModelScreenWidget {
        public static final String TAG_NAME = "link";
        private final Link link;
        private final ScreenImage image;

        public ScreenLink(ModelScreen modelScreen, Element linkElement) {
            super(modelScreen, linkElement);
            this.link = new Link(linkElement);
            Element imageElement = UtilXml.firstChildElement(linkElement, "image");
            if (imageElement != null) {
                this.image = new ScreenImage(modelScreen, imageElement);
            } else {
                this.image = null;
            }
        }

        @Override
        public String getName() {
            return link.getName();
        }

        public String getText(Map<String, Object> context) {
            return link.getText(context);
        }

        public String getId(Map<String, Object> context) {
            return link.getId(context);
        }

        public String getStyle(Map<String, Object> context) {
            return link.getStyle(context);
        }

        public String getTarget(Map<String, Object> context) {
            return link.getTarget(context);
        }

        public String getName(Map<String, Object> context) {
            return link.getName(context);
        }

        public String getTargetWindow(Map<String, Object> context) {
            return link.getTargetWindow(context);
        }

        public String getUrlMode() {
            return link.getUrlMode();
        }

        public String getPrefix(Map<String, Object> context) {
            return link.getPrefix(context);
        }

        public boolean getFullPath() {
            return link.getFullPath();
        }

        public boolean getSecure() {
            return link.getSecure();
        }

        public boolean getEncode() {
            return link.getEncode();
        }

        public ScreenImage getImage() {
            return image;
        }

        public String getLinkType() {
            return link.getLinkType();
        }

        public String getWidth() {
            return link.getWidth();
        }

        public String getHeight() {
            return link.getHeight();
        }

        public Map<String, String> getParameterMap(Map<String, Object> context) {
            return link.getParameterMap(context);
        }

        public Map<String, String> getParameterMap(Map<String, Object> context, boolean propagateCallback) {
            return link.getParameterMap(context, propagateCallback);
        }

        public FlexibleStringExpander getTextExdr() {
            return link.getTextExdr();
        }

        public FlexibleStringExpander getIdExdr() {
            return link.getIdExdr();
        }

        public FlexibleStringExpander getStyleExdr() {
            return link.getStyleExdr();
        }

        public FlexibleStringExpander getTargetExdr() {
            return link.getTargetExdr();
        }

        public FlexibleStringExpander getTargetWindowExdr() {
            return link.getTargetWindowExdr();
        }

        public FlexibleStringExpander getPrefixExdr() {
            return link.getPrefixExdr();
        }

        public FlexibleStringExpander getNameExdr() {
            return link.getNameExdr();
        }

        public List<Parameter> getParameterList() {
            return link.getParameterList();
        }

        public AutoServiceParameters getAutoServiceParameters() {
            return link.getAutoServiceParameters();
        }

        public AutoEntityParameters getAutoEntityParameters() {
            return link.getAutoEntityParameters();
        }

        @Override
        public void renderWidgetString(Appendable writer, Map<String, Object> context, ScreenStringRenderer screenStringRenderer) {
            try {
                screenStringRenderer.renderLink(writer, context, this);
            } catch (IOException e) {
                String errMsg = "Error rendering link with id [" + link.getId(context) + "]: " + e.toString();
                Debug.logError(e, errMsg, MODULE);
                throw new RuntimeException(errMsg);
            }
        }

        @Override
        public void accept(ModelWidgetVisitor visitor) throws Exception {
            visitor.visit(this);
        }

        public Link getLink() {
            return link;
        }
    }

    public static final class ScreenImage extends ModelScreenWidget {
        public static final String TAG_NAME = "image";
        private final Image image;

        @Override
        public String getName() {
            return image.getName();
        }

        public String getSrc(Map<String, Object> context) {
            return image.getSrc(context);
        }

        public String getId(Map<String, Object> context) {
            return image.getId(context);
        }

        public String getStyle(Map<String, Object> context) {
            return image.getStyle(context);
        }

        public String getWidth(Map<String, Object> context) {
            return image.getWidth(context);
        }

        public String getHeight(Map<String, Object> context) {
            return image.getHeight(context);
        }

        public String getBorder(Map<String, Object> context) {
            return image.getBorder(context);
        }

        public String getAlt(Map<String, Object> context) {
            return image.getAlt(context);
        }

        public String getUrlMode() {
            return image.getUrlMode();
        }

        public FlexibleStringExpander getSrcExdr() {
            return image.getSrcExdr();
        }

        public FlexibleStringExpander getIdExdr() {
            return image.getIdExdr();
        }

        public FlexibleStringExpander getStyleExdr() {
            return image.getStyleExdr();
        }

        public FlexibleStringExpander getWidthExdr() {
            return image.getWidthExdr();
        }

        public FlexibleStringExpander getHeightExdr() {
            return image.getHeightExdr();
        }

        public FlexibleStringExpander getBorderExdr() {
            return image.getBorderExdr();
        }

        public FlexibleStringExpander getAlt() {
            return image.getAlt();
        }

        public ScreenImage(ModelScreen modelScreen, Element imageElement) {
            super(modelScreen, imageElement);
            this.image = new Image(imageElement);
        }

        @Override
        public void renderWidgetString(Appendable writer, Map<String, Object> context, ScreenStringRenderer screenStringRenderer) {
            try {
                screenStringRenderer.renderImage(writer, context, this);
            } catch (IOException e) {
                String errMsg = "Error rendering image with id [" + image.getId(context) + "]: " + e.toString();
                Debug.logError(e, errMsg, MODULE);
                throw new RuntimeException(errMsg);
            }
        }

        @Override
        public void accept(ModelWidgetVisitor visitor) throws Exception {
            visitor.visit(this);
        }

        public Image getImage() {
            return image;
        }
    }

    public static final class PortalPage extends ModelScreenWidget {
        public static final String TAG_NAME = "include-portal-page";
        private final FlexibleStringExpander idExdr;
        private final FlexibleStringExpander confModeExdr;
        private final Boolean usePrivate;

        public PortalPage(ModelScreen modelScreen, Element portalPageElement) {
            super(modelScreen, portalPageElement);
            this.idExdr = FlexibleStringExpander.getInstance(portalPageElement.getAttribute("id"));
            this.confModeExdr = FlexibleStringExpander.getInstance(portalPageElement.getAttribute("conf-mode"));
            this.usePrivate = !("false".equals(portalPageElement.getAttribute("use-private")));
        }

        private GenericValue getPortalPageValue(Map<String, Object> context) {
            Delegator delegator = (Delegator) context.get("delegator");
            String expandedPortalPageId = getId(context);
            GenericValue portalPage = null;
            if (!expandedPortalPageId.isEmpty()) {
                if (usePrivate) {
                    portalPage = PortalPageWorker.getPortalPage(expandedPortalPageId, context);
                } else {
                    try {
                        portalPage = EntityQuery.use(delegator)
                                                .from("PortalPage")
                                                .where("portalPageId", expandedPortalPageId)
                                                .cache().queryOne();
                    } catch (GenericEntityException e) {
                        throw new RuntimeException(e);
                    }
                }
            }
            if (portalPage == null) {
                String errMsg = "Could not find PortalPage with portalPageId [" + expandedPortalPageId + "] ";
                Debug.logError(errMsg, MODULE);
            }
            return portalPage;
        }

        @Override
        public void renderWidgetString(Appendable writer, Map<String, Object> context,
                ScreenStringRenderer screenStringRenderer) throws GeneralException, IOException {
            GenericValue portalPage = getPortalPageValue(context);
            if (portalPage != null) {
                try {
                    Delegator delegator = (Delegator) context.get("delegator");
                    List<GenericValue> portalPageColumns = null;
                    List<GenericValue> portalPagePortlets = null;
                    List<GenericValue> portletAttributes = null;
                    String actualPortalPageId = portalPage.getString("portalPageId");
                    portalPageColumns = EntityQuery.use(delegator)
                                                   .from("PortalPageColumn")
                                                   .where("portalPageId", actualPortalPageId)
                                                   .orderBy("columnSeqId")
                                                   .cache(true)
                                                   .queryList();

                    // Renders the portalPage header
                    screenStringRenderer.renderPortalPageBegin(writer, context, this);

                    // First column has no previous column
                    String prevColumnSeqId = "";

                    // Iterates through the PortalPage columns
                    ListIterator<GenericValue> columnsIterator = portalPageColumns.listIterator();
                    while (columnsIterator.hasNext()) {
                        GenericValue columnValue = columnsIterator.next();
                        String columnSeqId = columnValue.getString("columnSeqId");

                        // Renders the portalPageColumn header
                        screenStringRenderer.renderPortalPageColumnBegin(writer, context, this, columnValue);

                        // Get the Portlets located in the current column
                        portalPagePortlets = EntityQuery.use(delegator)
                                                        .from("PortalPagePortletView")
                                                        .where("portalPageId", portalPage.getString("portalPageId"), "columnSeqId", columnSeqId)
                                                        .orderBy("sequenceNum")
                                                        .queryList();
                        // First Portlet in a Column has no previous Portlet
                        String prevPortletId = "";
                        String prevPortletSeqId = "";

                        // If this is not the last column, get the next columnSeqId
                        String nextColumnSeqId = "";
                        if (columnsIterator.hasNext()) {
                            nextColumnSeqId = portalPageColumns.get(columnsIterator.nextIndex()).getString("columnSeqId");
                        }

                        // Iterates through the Portlets in the Column
                        ListIterator<GenericValue> portletsIterator = portalPagePortlets.listIterator();
                        while (portletsIterator.hasNext()) {
                            GenericValue portletValue = portletsIterator.next();

                            // If not the last portlet in the column, get the next nextPortletId and nextPortletSeqId
                            String nextPortletId = "";
                            String nextPortletSeqId = "";
                            if (portletsIterator.hasNext()) {
                                nextPortletId = portalPagePortlets.get(portletsIterator.nextIndex()).getString("portalPortletId");
                                nextPortletSeqId = portalPagePortlets.get(portletsIterator.nextIndex()).getString("portletSeqId");
                            }

                            // Set info to allow portlet movement in the page
                            context.put("prevPortletId", prevPortletId);
                            context.put("prevPortletSeqId", prevPortletSeqId);
                            context.put("nextPortletId", nextPortletId);
                            context.put("nextPortletSeqId", nextPortletSeqId);
                            context.put("prevColumnSeqId", prevColumnSeqId);
                            context.put("nextColumnSeqId", nextColumnSeqId);

                            // Get portlet's attributes
                            portletAttributes = EntityQuery.use(delegator)
                                                           .from("PortletAttribute")
                                                           .where("portalPageId", portletValue.get("portalPageId"),
                                                                   "portalPortletId", portletValue.get("portalPortletId"),
                                                                   "portletSeqId", portletValue.get("portletSeqId"))
                                                           .queryList();

                            ListIterator<GenericValue> attributesIterator = portletAttributes.listIterator();
                            while (attributesIterator.hasNext()) {
                                GenericValue attribute = attributesIterator.next();
                                context.put(attribute.getString("attrName"), attribute.getString("attrValue"));
                            }

                            // Renders the portalPagePortlet
                            screenStringRenderer.renderPortalPagePortletBegin(writer, context, this, portletValue);
                            screenStringRenderer.renderPortalPagePortletBody(writer, context, this, portletValue);
                            screenStringRenderer.renderPortalPagePortletEnd(writer, context, this, portletValue);

                            // Remove the portlet's attributes so that these are not available for other portlets
                            while (attributesIterator.hasPrevious()) {
                                GenericValue attribute = attributesIterator.previous();
                                context.remove(attribute.getString("attrName"));
                            }

                            // Uses the actual portlet as prevPortlet for next iteration
                            prevPortletId = (String) portletValue.get("portalPortletId");
                            prevPortletSeqId = (String) portletValue.get("portletSeqId");
                        }
                        // Renders the portalPageColumn footer
                        screenStringRenderer.renderPortalPageColumnEnd(writer, context, this, columnValue);

                        // Uses the actual columnSeqId as prevColumnSeqId for next iteration
                        prevColumnSeqId = columnSeqId;
                    }
                    // Renders the portalPage footer
                    screenStringRenderer.renderPortalPageEnd(writer, context, this);
                } catch (IOException | GenericEntityException e) {
                    String errMsg = "Error rendering PortalPage with portalPageId [" + getId(context) + "]: " + e.toString();
                    Debug.logError(e, errMsg, MODULE);
                    throw new RuntimeException(errMsg);
                }
            } else {
                String errMsg = "Error rendering PortalPage, it's null";
                Debug.logError(errMsg, MODULE);
            }
        }

        public String getId(Map<String, Object> context) {
            return this.idExdr.expandString(context);
        }

        public String getOriginalPortalPageId(Map<String, Object> context) {
            GenericValue portalPage = getPortalPageValue(context);
            return portalPage.getString("originalPortalPageId");
        }

        public String getActualPortalPageId(Map<String, Object> context) {
            GenericValue portalPage = getPortalPageValue(context);
            return portalPage.getString("portalPageId");
        }

        public String getConfMode(Map<String, Object> context) {
            return this.confModeExdr.expandString(context);
        }

        public String getUsePrivate() {
            return Boolean.toString(this.usePrivate);
        }

        @Override
        public void accept(ModelWidgetVisitor visitor) throws Exception {
            visitor.visit(this);
        }

        public FlexibleStringExpander getIdExdr() {
            return idExdr;
        }

        public FlexibleStringExpander getConfModeExdr() {
            return confModeExdr;
        }
    }

}
