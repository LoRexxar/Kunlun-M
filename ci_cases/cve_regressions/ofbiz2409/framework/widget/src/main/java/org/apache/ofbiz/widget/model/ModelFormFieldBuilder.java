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

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.apache.ofbiz.base.util.Debug;
import org.apache.ofbiz.base.util.StringUtil;
import org.apache.ofbiz.base.util.UtilMisc;
import org.apache.ofbiz.base.util.UtilValidate;
import org.apache.ofbiz.base.util.UtilXml;
import org.apache.ofbiz.base.util.collections.FlexibleMapAccessor;
import org.apache.ofbiz.base.util.string.FlexibleStringExpander;
import org.apache.ofbiz.entity.GenericEntityException;
import org.apache.ofbiz.entity.model.ModelEntity;
import org.apache.ofbiz.entity.model.ModelField;
import org.apache.ofbiz.entity.model.ModelReader;
import org.apache.ofbiz.service.DispatchContext;
import org.apache.ofbiz.service.GenericServiceException;
import org.apache.ofbiz.service.ModelParam;
import org.apache.ofbiz.service.ModelService;
import org.apache.ofbiz.widget.model.ModelForm.UpdateArea;
import org.apache.ofbiz.widget.model.ModelFormField.CheckField;
import org.apache.ofbiz.widget.model.ModelFormField.ContainerField;
import org.apache.ofbiz.widget.model.ModelFormField.DateFindField;
import org.apache.ofbiz.widget.model.ModelFormField.DateTimeField;
import org.apache.ofbiz.widget.model.ModelFormField.DisplayEntityField;
import org.apache.ofbiz.widget.model.ModelFormField.DisplayField;
import org.apache.ofbiz.widget.model.ModelFormField.DropDownField;
import org.apache.ofbiz.widget.model.ModelFormField.FileField;
import org.apache.ofbiz.widget.model.ModelFormField.FormField;
import org.apache.ofbiz.widget.model.ModelFormField.GridField;
import org.apache.ofbiz.widget.model.ModelFormField.HiddenField;
import org.apache.ofbiz.widget.model.ModelFormField.HyperlinkField;
import org.apache.ofbiz.widget.model.ModelFormField.IgnoredField;
import org.apache.ofbiz.widget.model.ModelFormField.ImageField;
import org.apache.ofbiz.widget.model.ModelFormField.LookupField;
import org.apache.ofbiz.widget.model.ModelFormField.MenuField;
import org.apache.ofbiz.widget.model.ModelFormField.OptionSource;
import org.apache.ofbiz.widget.model.ModelFormField.PasswordField;
import org.apache.ofbiz.widget.model.ModelFormField.RadioField;
import org.apache.ofbiz.widget.model.ModelFormField.RangeFindField;
import org.apache.ofbiz.widget.model.ModelFormField.ResetField;
import org.apache.ofbiz.widget.model.ModelFormField.ScreenField;
import org.apache.ofbiz.widget.model.ModelFormField.SubmitField;
import org.apache.ofbiz.widget.model.ModelFormField.TextField;
import org.apache.ofbiz.widget.model.ModelFormField.TextFindField;
import org.apache.ofbiz.widget.model.ModelFormField.TextareaField;
import org.w3c.dom.Element;

/**
 * A <code>ModelFormField</code> builder.
 */
public class ModelFormFieldBuilder {

    private static final String MODULE = ModelFormFieldBuilder.class.getName();

    private FlexibleStringExpander action = FlexibleStringExpander.getInstance("");
    private String attributeName = "";
    private boolean encodeOutput = true;
    private String entityName = "";
    private FlexibleMapAccessor<Object> entryAcsr = null;
    private String event = "";
    private FieldInfo fieldInfo = null;
    private String fieldName = "";
    private String fieldType = null;
    private String headerLink = "";
    private String headerLinkStyle = "";
    private String idName = "";
    private FlexibleMapAccessor<Map<String, ? extends Object>> mapAcsr = null;
    private ModelForm modelForm = null;
    private String name = "";
    private List<UpdateArea> onChangeUpdateAreas = new ArrayList<>();
    private List<UpdateArea> onClickUpdateAreas = new ArrayList<>();
    private FlexibleStringExpander parameterName = FlexibleStringExpander.getInstance("");
    private Integer position = null;
    private String redWhen = "";
    private Boolean requiredField = null;
    private String requiredFieldStyle = "";
    private boolean separateColumn = false;
    private String serviceName = "";
    private Boolean sortField = null;
    private String sortFieldAscStyle = "";
    private String sortFieldDescStyle = "";
    private String sortFieldHelpText = "";
    private String sortFieldStyle = "";
    private FlexibleStringExpander title = FlexibleStringExpander.getInstance("");
    private String titleAreaStyle = "";
    private String titleStyle = "";
    private FlexibleStringExpander tooltip = FlexibleStringExpander.getInstance("");
    private String tooltipStyle = "";
    private FlexibleStringExpander useWhen = FlexibleStringExpander.getInstance("");
    private FlexibleStringExpander ignoreWhen = FlexibleStringExpander.getInstance("");
    private String widgetAreaStyle = "";
    private String widgetStyle = "";
    private String parentFormName = "";
    private String tabindex = "";
    private String conditionGroup = "";
    private FlexibleStringExpander disabled = FlexibleStringExpander.getInstance("");

    protected static final List<String> NUMERIC_FIELD_TYPES = Collections.unmodifiableList(UtilMisc.toList(
            "floating-point", "numeric", "fixed-point",
            "currency-amount", "currency-precise"));
    protected static final List<String> TEXT_FIELD_TYPES = Collections.unmodifiableList(UtilMisc.toList(
            "id", "id-long", "id-vlong",
            "very-short", "name", "short-varchar",
            "value", "comment", "description",
            "long-varchar", "url", "email"));
    protected static final Map<String, Integer> TEXT_SIZE_BY_FIELD_TYPES = Collections.unmodifiableMap(UtilMisc.toMap(
            "id", 20,
            "id-long", 40,
            "id-vlong", 60,
            "very-short", 6,
            "name", 40,
            "short-varchar", 40,
            "value", 60,
            "comment", 60,
            "description", 60,
            "long-varchar", 60,
            "url", 60,
            "email", 60));
    protected static final Map<String, Integer> TEXT_MAX_SIZE_BY_FIELD_TYPES = Collections.unmodifiableMap(UtilMisc.toMap(
            "id", 20,
            "id-long", 60,
            "id-vlong", 250,
            "very-short", 10,
            "name", 60,
            "short-varchar", 40,
            "value", 250,
            "comment", 250,
            "description", 250,
            "long-varchar", 250,
            "url", 250,
            "email", 250));
    protected static final List<String> DATA_FIELD_TYPES = Collections.unmodifiableList(UtilMisc.toList(
            "date-time", "date", "time"));

    public ModelFormFieldBuilder() {
    }

    /** XML Constructor */
    public ModelFormFieldBuilder(Element fieldElement, ModelForm modelForm, ModelReader entityModelReader,
            DispatchContext dispatchContext) {
        String name = fieldElement.getAttribute("name");
        this.action = FlexibleStringExpander.getInstance(fieldElement.getAttribute("action"));
        this.attributeName = UtilXml.checkEmpty(fieldElement.getAttribute("attribute-name"), name);
        this.encodeOutput = !"false".equals(fieldElement.getAttribute("encode-output"));
        this.entityName = fieldElement.getAttribute("entity-name");
        this.entryAcsr = FlexibleMapAccessor.getInstance(UtilXml.checkEmpty(fieldElement.getAttribute("entry-name"), name));
        this.event = fieldElement.getAttribute("event");
        this.fieldName = UtilXml.checkEmpty(fieldElement.getAttribute("field-name"), name);
        this.headerLink = fieldElement.getAttribute("header-link");
        this.headerLinkStyle = fieldElement.getAttribute("header-link-style");
        this.idName = fieldElement.getAttribute("id-name");
        this.mapAcsr = FlexibleMapAccessor.getInstance(fieldElement.getAttribute("map-name"));
        this.modelForm = modelForm;
        this.name = name;
        this.parameterName = FlexibleStringExpander.getInstance(UtilXml.checkEmpty(fieldElement.getAttribute("parameter-name"), name));
        String positionAtttr = fieldElement.getAttribute("position");
        Integer position = null;
        if (!positionAtttr.isEmpty()) {
            position = Integer.parseInt(positionAtttr);
        }
        this.position = position;
        this.redWhen = fieldElement.getAttribute("red-when");
        String requiredField = fieldElement.getAttribute("required-field");
        this.requiredField = requiredField.isEmpty() ? null : "true".equals(requiredField);
        this.requiredFieldStyle = fieldElement.getAttribute("required-field-style");
        this.separateColumn = "true".equals(fieldElement.getAttribute("separate-column"));
        this.serviceName = fieldElement.getAttribute("service-name");
        String sortField = fieldElement.getAttribute("sort-field");
        this.sortField = sortField.isEmpty() ? null : "true".equals(sortField);
        this.sortFieldAscStyle = fieldElement.getAttribute("sort-field-asc-style");
        this.sortFieldDescStyle = fieldElement.getAttribute("sort-field-desc-style");
        this.sortFieldHelpText = fieldElement.getAttribute("sort-field-help-text");
        this.sortFieldStyle = fieldElement.getAttribute("sort-field-style");
        this.title = FlexibleStringExpander.getInstance(fieldElement.getAttribute("title"));
        this.titleAreaStyle = fieldElement.getAttribute("title-area-style");
        this.titleStyle = fieldElement.getAttribute("title-style");
        this.tooltip = FlexibleStringExpander.getInstance(fieldElement.getAttribute("tooltip"));
        this.tooltipStyle = fieldElement.getAttribute("tooltip-style");
        this.useWhen = FlexibleStringExpander.getInstance(fieldElement.getAttribute("use-when"));
        this.ignoreWhen = FlexibleStringExpander.getInstance(fieldElement.getAttribute("ignore-when"));
        this.widgetAreaStyle = fieldElement.getAttribute("widget-area-style");
        this.widgetStyle = fieldElement.getAttribute("widget-style");
        this.parentFormName = fieldElement.getAttribute("form-name");
        this.tabindex = fieldElement.getAttribute("tabindex");
        this.conditionGroup = fieldElement.getAttribute("condition-group");
        this.disabled = FlexibleStringExpander.getInstance(fieldElement.getAttribute("disabled"));
        Element childElement = null;
        List<? extends Element> subElements = UtilXml.childElementList(fieldElement);
        for (Element subElement : subElements) {
            String subElementName = UtilXml.getTagNameIgnorePrefix(subElement);
            if ("on-field-event-update-area".equals(subElementName)) {
                UpdateArea updateArea = new UpdateArea(subElement);
                if ("change".equals(updateArea.getEventType())) {
                    onChangeUpdateAreas.add(updateArea);
                } else if ("click".equals(updateArea.getEventType())) {
                    onClickUpdateAreas.add(updateArea);
                }
            } else {
                if (this.fieldType != null) {
                    throw new IllegalArgumentException("Multiple field types found: " + this.fieldType + ", " + subElementName);
                }
                this.fieldType = subElementName;
                childElement = subElement;
            }
        }
        if (UtilValidate.isEmpty(this.fieldType)) {
            this.induceFieldInfo(modelForm, null, entityModelReader, dispatchContext);
        } else if ("display".equals(this.fieldType)) {
            this.fieldInfo = new DisplayField(childElement, null);
        } else if ("display-entity".equals(this.fieldType)) {
            this.fieldInfo = new DisplayEntityField(childElement, null);
        } else if ("hyperlink".equals(this.fieldType)) {
            this.fieldInfo = new HyperlinkField(childElement, null);
        } else if ("text".equals(this.fieldType)) {
            this.fieldInfo = new TextField(childElement, null);
        } else if ("textarea".equals(this.fieldType)) {
            this.fieldInfo = new TextareaField(childElement, null);
        } else if ("date-time".equals(this.fieldType)) {
            this.fieldInfo = new DateTimeField(childElement, null);
        } else if ("drop-down".equals(this.fieldType)) {
            this.fieldInfo = new DropDownField(childElement, null);
        } else if ("check".equals(this.fieldType)) {
            this.fieldInfo = new CheckField(childElement, null);
        } else if ("radio".equals(this.fieldType)) {
            this.fieldInfo = new RadioField(childElement, null);
        } else if ("submit".equals(this.fieldType)) {
            this.fieldInfo = new SubmitField(childElement, null);
        } else if ("reset".equals(this.fieldType)) {
            this.fieldInfo = new ResetField(childElement, null);
        } else if ("hidden".equals(this.fieldType)) {
            this.fieldInfo = new HiddenField(childElement, null);
        } else if ("ignored".equals(this.fieldType)) {
            this.fieldInfo = new IgnoredField(childElement, null);
        } else if ("text-find".equals(this.fieldType)) {
            this.fieldInfo = new TextFindField(childElement, null);
        } else if ("date-find".equals(this.fieldType)) {
            this.fieldInfo = new DateFindField(childElement, null);
        } else if ("range-find".equals(this.fieldType)) {
            this.fieldInfo = new RangeFindField(childElement, null);
        } else if ("lookup".equals(this.fieldType)) {
            this.fieldInfo = new LookupField(childElement, null);
        } else if ("include-menu".equals(this.fieldType)) {
            this.fieldInfo = new MenuField(childElement, null);
        } else if ("include-form".equals(this.fieldType)) {
            this.fieldInfo = new FormField(childElement, null);
        } else if ("include-grid".equals(this.fieldType)) {
            this.fieldInfo = new GridField(childElement, null);
        } else if ("include-screen".equals(this.fieldType)) {
            this.fieldInfo = new ScreenField(childElement, null);
        } else if ("file".equals(this.fieldType)) {
            this.fieldInfo = new FileField(childElement, null);
        } else if ("password".equals(this.fieldType)) {
            this.fieldInfo = new PasswordField(childElement, null);
        } else if ("image".equals(this.fieldType)) {
            this.fieldInfo = new ImageField(childElement, null);
        } else if ("container".equals(this.fieldType)) {
            this.fieldInfo = new ContainerField(childElement, null);
        } else {
            throw new IllegalArgumentException("The field sub-element with name " + this.fieldType + " is not supported");
        }
    }

    public ModelFormFieldBuilder(ModelFormField modelFormField) {
        this.action = modelFormField.getAction();
        this.attributeName = modelFormField.getAttributeName();
        this.encodeOutput = modelFormField.getEncodeOutput();
        this.entityName = modelFormField.getEntityName();
        this.entryAcsr = modelFormField.getEntryAcsr();
        this.event = modelFormField.getEvent();
        this.fieldInfo = modelFormField.getFieldInfo();
        this.fieldName = modelFormField.getFieldName();
        this.headerLink = modelFormField.getHeaderLink();
        this.headerLinkStyle = modelFormField.getHeaderLinkStyle();
        this.idName = modelFormField.getIdName();
        this.mapAcsr = modelFormField.getMapAcsr();
        this.modelForm = modelFormField.getModelForm();
        this.name = modelFormField.getName();
        this.onChangeUpdateAreas.addAll(modelFormField.getOnChangeUpdateAreas());
        this.onClickUpdateAreas.addAll(modelFormField.getOnClickUpdateAreas());
        this.parameterName = modelFormField.getParameterName();
        this.position = modelFormField.getPosition();
        this.redWhen = modelFormField.getRedWhen();
        this.requiredField = modelFormField.getRequiredField();
        this.requiredFieldStyle = modelFormField.getRequiredFieldStyle();
        this.separateColumn = modelFormField.getSeparateColumn();
        this.serviceName = modelFormField.getServiceName();
        this.sortField = modelFormField.getSortField();
        this.sortFieldAscStyle = modelFormField.getSortFieldAscStyle();
        this.sortFieldDescStyle = modelFormField.getSortFieldDescStyle();
        this.sortFieldHelpText = modelFormField.getSortFieldHelpText();
        this.sortFieldStyle = modelFormField.getSortFieldStyle();
        this.title = modelFormField.getTitle();
        this.titleAreaStyle = modelFormField.getTitleAreaStyle();
        this.titleStyle = modelFormField.getTitleStyle();
        this.tooltip = modelFormField.getTooltip();
        this.tooltipStyle = modelFormField.getTooltipStyle();
        this.useWhen = modelFormField.getUseWhen();
        this.widgetAreaStyle = modelFormField.getWidgetAreaStyle();
        this.widgetStyle = modelFormField.getWidgetStyle();
        this.parentFormName = modelFormField.getParentFormName();
        this.tabindex = modelFormField.getTabindex();
        this.conditionGroup = modelFormField.getConditionGroup();
        this.disabled = modelFormField.getDisabledSpec();
    }

    public ModelFormFieldBuilder(ModelFormFieldBuilder builder) {
        this.action = builder.getAction();
        this.attributeName = builder.getAttributeName();
        this.encodeOutput = builder.getEncodeOutput();
        this.entityName = builder.getEntityName();
        this.entryAcsr = builder.getEntryAcsr();
        this.event = builder.getEvent();
        this.fieldInfo = builder.getFieldInfo();
        this.fieldName = builder.getFieldName();
        this.headerLink = builder.getHeaderLink();
        this.headerLinkStyle = builder.getHeaderLinkStyle();
        this.idName = builder.getIdName();
        this.mapAcsr = builder.getMapAcsr();
        this.modelForm = builder.getModelForm();
        this.name = builder.getName();
        this.onChangeUpdateAreas.addAll(builder.getOnChangeUpdateAreas());
        this.onClickUpdateAreas.addAll(builder.getOnClickUpdateAreas());
        this.parameterName = builder.getParameterName();
        this.position = builder.getPosition();
        this.redWhen = builder.getRedWhen();
        this.requiredField = builder.getRequiredField();
        this.requiredFieldStyle = builder.getRequiredFieldStyle();
        this.separateColumn = builder.getSeparateColumn();
        this.serviceName = builder.getServiceName();
        this.sortField = builder.getSortField();
        this.sortFieldAscStyle = builder.getSortFieldAscStyle();
        this.sortFieldDescStyle = builder.getSortFieldDescStyle();
        this.sortFieldHelpText = builder.getSortFieldHelpText();
        this.sortFieldStyle = builder.getSortFieldStyle();
        this.title = builder.getTitle();
        this.titleAreaStyle = builder.getTitleAreaStyle();
        this.titleStyle = builder.getTitleStyle();
        this.tooltip = builder.getTooltip();
        this.tooltipStyle = builder.getTooltipStyle();
        this.useWhen = builder.getUseWhen();
        this.widgetAreaStyle = builder.getWidgetAreaStyle();
        this.widgetStyle = builder.getWidgetStyle();
        this.parentFormName = builder.getParentFormName();
        this.tabindex = builder.getTabindex();
        this.conditionGroup = builder.getConditionGroup();
        this.disabled = builder.getDisabledSpec();
    }

    /**
     * Add on change update area model form field builder.*
     * @param onChangeUpdateArea the on change update area
     * @return the model form field builder
     */
    public ModelFormFieldBuilder addOnChangeUpdateArea(UpdateArea onChangeUpdateArea) {
        this.onChangeUpdateAreas.add(onChangeUpdateArea);
        return this;
    }

    /**
     * Add on click update area model form field builder.*
     * @param onClickUpdateArea the on click update area
     * @return the model form field builder
     */
    public ModelFormFieldBuilder addOnClickUpdateArea(UpdateArea onClickUpdateArea) {
        this.onClickUpdateAreas.add(onClickUpdateArea);
        return this;
    }

    /**
     * Build model form field.*
     * @return the model form field
     */
    public ModelFormField build() {
        return ModelFormField.from(this);
    }

    /**
     * Gets action.*
     * @return the action
     */
    public FlexibleStringExpander getAction() {
        return action;
    }

    /**
     * Gets attribute name.*
     * @return the attribute name
     */
    public String getAttributeName() {
        return attributeName;
    }

    /**
     * Gets encode output.*
     * @return the encode output
     */
    public boolean getEncodeOutput() {
        return encodeOutput;
    }

    /**
     * Gets entity name.*
     * @return the entity name
     */
    public String getEntityName() {
        return entityName;
    }

    /**
     * Gets entry acsr.*
     * @return the entry acsr
     */
    public FlexibleMapAccessor<Object> getEntryAcsr() {
        return entryAcsr;
    }

    /**
     * Gets event.*
     * @return the event
     */
    public String getEvent() {
        return event;
    }

    /**
     * Gets field info.*
     * @return the field info
     */
    public FieldInfo getFieldInfo() {
        return fieldInfo;
    }

    /**
     * Gets field name.*
     * @return the field name
     */
    public String getFieldName() {
        return fieldName;
    }

    /**
     * Gets field type.*
     * @return the field type
     */
    public String getFieldType() {
        return fieldType;
    }

    /**
     * Gets header link.*
     * @return the header link
     */
    public String getHeaderLink() {
        return headerLink;
    }

    /**
     * Gets header link style.*
     * @return the header link style
     */
    public String getHeaderLinkStyle() {
        return headerLinkStyle;
    }

    /**
     * Gets id name.*
     * @return the id name
     */
    public String getIdName() {
        return idName;
    }

    /**
     * Gets map acsr.*
     * @return the map acsr
     */
    public FlexibleMapAccessor<Map<String, ? extends Object>> getMapAcsr() {
        return mapAcsr;
    }

    /**
     * Gets model form.*
     * @return the model form
     */
    public ModelForm getModelForm() {
        return modelForm;
    }

    /**
     * Gets name.*
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * Gets on change update areas.*
     * @return the on change update areas
     */
    public List<UpdateArea> getOnChangeUpdateAreas() {
        return onChangeUpdateAreas;
    }

    /**
     * Gets on click update areas.*
     * @return the on click update areas
     */
    public List<UpdateArea> getOnClickUpdateAreas() {
        return onClickUpdateAreas;
    }

    /**
     * Gets parameter name.*
     * @return the parameter name
     */
    public FlexibleStringExpander getParameterName() {
        return parameterName;
    }

    /**
     * Gets position.*
     * @return the position
     */
    public Integer getPosition() {
        return position;
    }

    /**
     * Gets red when.*
     * @return the red when
     */
    public String getRedWhen() {
        return redWhen;
    }

    /**
     * Gets required field.*
     * @return the required field
     */
    public Boolean getRequiredField() {
        return requiredField;
    }

    /**
     * Gets required field style.*
     * @return the required field style
     */
    public String getRequiredFieldStyle() {
        return requiredFieldStyle;
    }

    /**
     * Gets separate column.*
     * @return the separate column
     */
    public boolean getSeparateColumn() {
        return separateColumn;
    }

    /**
     * Gets service name.*
     * @return the service name
     */
    public String getServiceName() {
        return serviceName;
    }

    /**
     * Gets sort field.*
     * @return the sort field
     */
    public Boolean getSortField() {
        return sortField;
    }

    /**
     * Gets sort field asc style.*
     * @return the sort field asc style
     */
    public String getSortFieldAscStyle() {
        return sortFieldAscStyle;
    }

    /**
     * Gets sort field desc style.*
     * @return the sort field desc style
     */
    public String getSortFieldDescStyle() {
        return sortFieldDescStyle;
    }

    /**
     * Gets sort field help text.*
     * @return the sort field help text
     */
    public String getSortFieldHelpText() {
        return sortFieldHelpText;
    }

    /**
     * Gets sort field style.*
     * @return the sort field style
     */
    public String getSortFieldStyle() {
        return sortFieldStyle;
    }

    /**
     * Gets title.*
     * @return the title
     */
    public FlexibleStringExpander getTitle() {
        return title;
    }

    /**
     * Gets title area style.*
     * @return the title area style
     */
    public String getTitleAreaStyle() {
        return titleAreaStyle;
    }

    /**
     * Gets title style.*
     * @return the title style
     */
    public String getTitleStyle() {
        return titleStyle;
    }

    /**
     * Gets tooltip.*
     * @return the tooltip
     */
    public FlexibleStringExpander getTooltip() {
        return tooltip;
    }

    /**
     * Gets tooltip style.*
     * @return the tooltip style
     */
    public String getTooltipStyle() {
        return tooltipStyle;
    }

    /**
     * Gets use when.*
     * @return the use when
     */
    public FlexibleStringExpander getUseWhen() {
        return useWhen;
    }

    /**
     * Gets ignore when.*
     * @return the ignore when
     */
    public FlexibleStringExpander getIgnoreWhen() {
        return ignoreWhen;
    }

    /**
     * Gets widget area style.*
     * @return the widget area style
     */
    public String getWidgetAreaStyle() {
        return widgetAreaStyle;
    }

    /**
     * Gets widget style.*
     * @return the widget style
     */
    public String getWidgetStyle() {
        return widgetStyle;
    }

    /**
     * Gets parent form name.*
     * @return the parent form name
     */
    public String getParentFormName() {
        return parentFormName;
    }

    /**
     * Gets tabindex.*
     * @return the tabindex
     */
    public String getTabindex() {
        return tabindex;
    }

    /**
     * Gets condition group.*
     * @return the condition group
     */
    public String getConditionGroup() {
        return conditionGroup;
    }

    /**
     * Gets disabled.*
     * @return the disabled
     */
    public FlexibleStringExpander getDisabledSpec() {
        return disabled;
    }

    private boolean induceFieldInfo(ModelForm modelForm, String defaultFieldType, ModelReader entityModelReader, DispatchContext dispatchContext) {
        if (induceFieldInfoFromEntityField(defaultFieldType, entityModelReader)) {
            return true;
        }
        if (induceFieldInfoFromServiceParam(defaultFieldType, entityModelReader, dispatchContext)) {
            return true;
        }
        return false;
    }

    /**
     * Induce field info from entity field boolean.
     * @param modelEntity the model entity
     * @param modelField the model field
     * @param defaultFieldType the default field type
     * @return the boolean
     */
    public boolean induceFieldInfoFromEntityField(ModelEntity modelEntity, ModelField modelField, String defaultFieldType) {
        if (modelEntity == null || modelField == null) {
            return false;
        }
        this.entityName = modelEntity.getEntityName();
        this.fieldName = modelField.getName();
        String fieldType = modelField.getType();
        if ("find".equals(defaultFieldType)) {
            if ("indicator".equals(fieldType)) {
                List<OptionSource> optionSources = UtilMisc.toList(
                        new ModelFormField.SingleOption("", null, null),
                        new ModelFormField.SingleOption("Y", null, null),
                        new ModelFormField.SingleOption("N", null, null));
                ModelFormField.DropDownField dropDownField = new ModelFormField.DropDownField(FieldInfo.SOURCE_AUTO_ENTITY,
                        optionSources);
                this.setFieldInfo(dropDownField);
            } else if (TEXT_FIELD_TYPES.contains(fieldType)) {
                ModelFormField.TextFindField textField = new ModelFormField.TextFindField(FieldInfo.SOURCE_AUTO_ENTITY,
                        TEXT_SIZE_BY_FIELD_TYPES.get(fieldType), TEXT_MAX_SIZE_BY_FIELD_TYPES.get(fieldType), null);
                this.setFieldInfo(textField);
            } else if (NUMERIC_FIELD_TYPES.contains(fieldType)) {
                ModelFormField.RangeFindField textField = new ModelFormField.RangeFindField(FieldInfo.SOURCE_AUTO_ENTITY, 6, null);
                this.setFieldInfo(textField);
            } else if (DATA_FIELD_TYPES.contains(fieldType)) {
                String type = fieldType;
                if ("date-time".equals(fieldType)) {
                    type = "timestamp";
                }
                ModelFormField.DateFindField dateTimeField = new ModelFormField.DateFindField(FieldInfo.SOURCE_AUTO_ENTITY, type);
                this.setFieldInfo(dateTimeField);
            } else {
                ModelFormField.TextFindField textField = new ModelFormField.TextFindField(FieldInfo.SOURCE_AUTO_ENTITY, null);
                this.setFieldInfo(textField);
            }
        } else if ("display".equals(defaultFieldType)) {
            ModelFormField.DisplayField displayField = new ModelFormField.DisplayField(FieldInfo.SOURCE_AUTO_ENTITY, null);
            this.setFieldInfo(displayField);
        } else if ("hidden".equals(defaultFieldType)) {
            ModelFormField.HiddenField hiddenField = new ModelFormField.HiddenField(FieldInfo.SOURCE_AUTO_ENTITY, null);
            this.setFieldInfo(hiddenField);
        } else {
            if ("indicator".equals(fieldType)) {
                List<OptionSource> optionSources = UtilMisc.toList(
                        new ModelFormField.SingleOption("Y", null, null),
                        new ModelFormField.SingleOption("N", null, null));
                ModelFormField.DropDownField dropDownField = new ModelFormField.DropDownField(FieldInfo.SOURCE_AUTO_ENTITY,
                        optionSources);
                this.setFieldInfo(dropDownField);
            } else if ("very-long".equals(fieldType)) {
                ModelFormField.TextareaField textareaField = new ModelFormField.TextareaField(FieldInfo.SOURCE_AUTO_ENTITY, null);
                this.setFieldInfo(textareaField);
            } else if (TEXT_FIELD_TYPES.contains(fieldType)) {
                ModelFormField.TextField textField = new ModelFormField.TextField(FieldInfo.SOURCE_AUTO_ENTITY,
                        TEXT_SIZE_BY_FIELD_TYPES.get(fieldType), TEXT_MAX_SIZE_BY_FIELD_TYPES.get(fieldType), null);
                this.setFieldInfo(textField);
            } else if (NUMERIC_FIELD_TYPES.contains(fieldType)) {
                ModelFormField.TextField textField = new ModelFormField.TextField(FieldInfo.SOURCE_AUTO_ENTITY, 6, null, null);
                this.setFieldInfo(textField);
            } else if (DATA_FIELD_TYPES.contains(fieldType)) {
                String type = fieldType;
                if ("date-time".equals(fieldType)) {
                    type = "timestamp";
                }
                ModelFormField.DateTimeField dateTimeField = new ModelFormField.DateTimeField(FieldInfo.SOURCE_AUTO_ENTITY, type);
                this.setFieldInfo(dateTimeField);
            } else {
                ModelFormField.TextField textField = new ModelFormField.TextField(FieldInfo.SOURCE_AUTO_ENTITY, null);
                this.setFieldInfo(textField);
            }
        }
        return true;
    }

    private boolean induceFieldInfoFromEntityField(String defaultFieldType, ModelReader entityModelReader) {
        if (UtilValidate.isEmpty(this.getEntityName()) || UtilValidate.isEmpty(this.getFieldName())) {
            return false;
        }
        try {
            ModelEntity modelEntity = entityModelReader.getModelEntity(this.getEntityName());
            ModelField modelField = modelEntity.getField(this.getFieldName());
            if (modelField != null) {
                // okay, populate using the entity field info...
                this.induceFieldInfoFromEntityField(modelEntity, modelField, defaultFieldType);
                return true;
            }
        } catch (GenericEntityException e) {
            Debug.logError(e, MODULE);
        }
        return false;
    }

    /**
     * Induce field info from service param boolean.
     * @param modelService     the model service
     * @param modelParam       the model param
     * @param defaultFieldType the default field type
     * @return the boolean
     */
    public boolean induceFieldInfoFromServiceParam(ModelService modelService, ModelParam modelParam, String defaultFieldType) {
        if (modelService == null || modelParam == null) {
            return false;
        }
        this.serviceName = modelService.getName();
        this.attributeName = modelParam.getName();
        String modelParamFieldType = computeFieldTypeToUse(modelParam.getType());
        FieldInfo fieldInfo = null;
        switch (defaultFieldType) {
        case "display":
            fieldInfo = new ModelFormField.DisplayField(FieldInfo.SOURCE_AUTO_SERVICE, null);
            break;
        case "hidden":
            fieldInfo = new ModelFormField.HiddenField(FieldInfo.SOURCE_AUTO_SERVICE, null);
            break;
        case "find":
            if ("text".equals(modelParamFieldType)) {
                fieldInfo = new ModelFormField.TextFindField(FieldInfo.SOURCE_AUTO_SERVICE, null);
            } else if ("numeric".equals(modelParamFieldType)) {
                fieldInfo = new ModelFormField.RangeFindField(FieldInfo.SOURCE_AUTO_SERVICE, 6, null);
            } else if ("timestamp".equals(modelParamFieldType)) {
                fieldInfo = new ModelFormField.DateFindField(FieldInfo.SOURCE_AUTO_SERVICE, "timestamp");
            } else if ("date".equals(modelParamFieldType)) {
                fieldInfo = new ModelFormField.DateFindField(FieldInfo.SOURCE_AUTO_SERVICE, "date");
            } else if ("time".equals(modelParamFieldType)) {
                fieldInfo = new ModelFormField.DateFindField(FieldInfo.SOURCE_AUTO_SERVICE, "time");
            }
            break;
        default: // default to "edit"
            if ("text".equals(modelParamFieldType)) {
                fieldInfo = new ModelFormField.TextField(FieldInfo.SOURCE_AUTO_SERVICE, null);
            } else if ("numeric".equals(modelParamFieldType)) {
                fieldInfo = new ModelFormField.TextField(FieldInfo.SOURCE_AUTO_SERVICE, 6, null, null);
            } else if ("timestamp".equals(modelParamFieldType)) {
                fieldInfo = new ModelFormField.DateTimeField(FieldInfo.SOURCE_AUTO_SERVICE, "timestamp");
            } else if ("date".equals(modelParamFieldType)) {
                fieldInfo = new ModelFormField.DateTimeField(FieldInfo.SOURCE_AUTO_SERVICE, "date");
            } else if ("time".equals(modelParamFieldType)) {
                fieldInfo = new ModelFormField.DateTimeField(FieldInfo.SOURCE_AUTO_SERVICE, "time");
            }
        }
        this.setFieldInfo(fieldInfo);
        return fieldInfo != null;
    }

    /**
     * For a service model parameter type, return the logique field type to use
     * If nothing found, return text
     * @param modelParamType
     * @return
     */
    private String computeFieldTypeToUse(String modelParamType) {
        final Map<String, String> switchType = UtilMisc.toMap("Double", "numeric",
                "Float", "numeric",
                "Long", "numeric",
                "Integer", "numeric",
                "BigDecimal", "numeric",
                "Timestamp", "timestamp",
                "Date", "date",
                "Time", "time");
        String typeToConvert = "";
        if (modelParamType.contains(".")) {
            LinkedList<String> splitString = new LinkedList<>(StringUtil.split(modelParamType, "."));
            typeToConvert = splitString.getLast();
        } else {
            typeToConvert = modelParamType;
        }
        return switchType.containsKey(typeToConvert) ? switchType.get(typeToConvert) : "text";
    }

    private boolean induceFieldInfoFromServiceParam(String defaultFieldType, ModelReader entityModelReader,
            DispatchContext dispatchContext) {
        if (UtilValidate.isEmpty(this.getServiceName()) || UtilValidate.isEmpty(this.getAttributeName())) {
            return false;
        }
        try {
            ModelService modelService = dispatchContext.getModelService(this.getServiceName());
            ModelParam modelParam = modelService.getParam(this.getAttributeName());
            if (modelParam != null) {
                if (UtilValidate.isNotEmpty(modelParam.getEntityName()) && UtilValidate.isNotEmpty(modelParam.getFieldName())) {
                    this.entityName = modelParam.getEntityName();
                    this.fieldName = modelParam.getFieldName();
                    if (this.induceFieldInfoFromEntityField(defaultFieldType, entityModelReader)) {
                        return true;
                    }
                }

                this.induceFieldInfoFromServiceParam(modelService, modelParam, defaultFieldType);
                return true;
            }
        } catch (GenericServiceException e) {
            Debug.logError(e,
                    "error getting service parameter definition for auto-field with serviceName: " + this.getServiceName()
                            + ", and attributeName: " + this.getAttributeName(), MODULE);
        }
        return false;
    }

    /**
     * Merge override model form field.
     * @param builder the builder
     */
    public void mergeOverrideModelFormField(ModelFormFieldBuilder builder) {
        if (builder == null) {
            return;
        }
        if (UtilValidate.isNotEmpty(builder.getName())) {
            this.name = builder.getName();
        }
        if (UtilValidate.isNotEmpty(builder.getMapAcsr())) {
            this.mapAcsr = builder.getMapAcsr();
        }
        if (UtilValidate.isNotEmpty(builder.getEntityName())) {
            this.entityName = builder.getEntityName();
        }
        if (UtilValidate.isNotEmpty(builder.getServiceName())) {
            this.serviceName = builder.getServiceName();
        }
        if (UtilValidate.isNotEmpty(builder.getEntryAcsr())) {
            this.entryAcsr = builder.getEntryAcsr();
        }
        if (UtilValidate.isNotEmpty(builder.getParameterName())) {
            this.parameterName = builder.getParameterName();
        }
        if (UtilValidate.isNotEmpty(builder.getFieldName())) {
            this.fieldName = builder.getFieldName();
        }
        if (!builder.getAttributeName().isEmpty()) {
            this.attributeName = builder.getAttributeName();
        }
        if (UtilValidate.isNotEmpty(builder.getTitle())) {
            this.title = builder.getTitle();
        }
        if (UtilValidate.isNotEmpty(builder.getTooltip())) {
            this.tooltip = builder.getTooltip();
        }
        if (builder.getSortField() != null) {
            this.sortField = builder.getSortField();
        }
        if (UtilValidate.isNotEmpty(builder.getSortFieldHelpText())) {
            this.sortFieldHelpText = builder.getSortFieldHelpText();
        }
        if (UtilValidate.isNotEmpty(builder.getTitleAreaStyle())) {
            this.titleAreaStyle = builder.getTitleAreaStyle();
        }
        if (UtilValidate.isNotEmpty(builder.getWidgetAreaStyle())) {
            this.widgetAreaStyle = builder.getWidgetAreaStyle();
        }
        if (UtilValidate.isNotEmpty(builder.getTitleStyle())) {
            this.titleStyle = builder.getTitleStyle();
        }
        if (UtilValidate.isNotEmpty(builder.getWidgetStyle())) {
            this.widgetStyle = builder.getWidgetStyle();
        }
        if (UtilValidate.isNotEmpty(builder.getRedWhen())) {
            this.redWhen = builder.getRedWhen();
        }
        if (UtilValidate.isNotEmpty(builder.getEvent())) {
            this.event = builder.getEvent();
        }
        if (!builder.getAction().isEmpty()) {
            this.action = builder.getAction();
        }
        if (UtilValidate.isNotEmpty(builder.getUseWhen())) {
            this.useWhen = builder.getUseWhen();
        }
        if (UtilValidate.isNotEmpty(builder.getIgnoreWhen())) {
            this.ignoreWhen = builder.getIgnoreWhen();
        }
        if (builder.getFieldInfo() != null) {
            this.setFieldInfo(builder.getFieldInfo());
        }
        if (UtilValidate.isNotEmpty(builder.getHeaderLink())) {
            this.headerLink = builder.getHeaderLink();
        }
        if (UtilValidate.isNotEmpty(builder.getHeaderLinkStyle())) {
            this.headerLinkStyle = builder.getHeaderLinkStyle();
        }
        if (UtilValidate.isNotEmpty(builder.getIdName())) {
            this.idName = builder.getIdName();
        }
        if (UtilValidate.isNotEmpty(builder.getOnChangeUpdateAreas())) {
            this.onChangeUpdateAreas.addAll(builder.getOnChangeUpdateAreas());
        }
        if (UtilValidate.isNotEmpty(builder.getOnClickUpdateAreas())) {
            this.onClickUpdateAreas.addAll(builder.getOnClickUpdateAreas());
        }
        if (UtilValidate.isNotEmpty(builder.getParentFormName())) {
            this.parentFormName = builder.getParentFormName();
        }
        if (UtilValidate.isNotEmpty(builder.getTabindex())) {
            this.tabindex = builder.getTabindex();
        }
        if (UtilValidate.isNotEmpty(builder.getConditionGroup())) {
            this.conditionGroup = builder.getConditionGroup();
        }
        this.encodeOutput = builder.getEncodeOutput();
        this.position = builder.getPosition();
        this.requiredField = builder.getRequiredField();
        this.separateColumn = builder.getSeparateColumn();
        this.disabled = builder.getDisabledSpec();
    }

    /**
     * Sets action.*
     * @param action the action
     * @return the action
     */
    public ModelFormFieldBuilder setAction(String action) {
        this.action = FlexibleStringExpander.getInstance(action);
        return this;
    }

    /**
     * Sets attribute name.*
     * @param attributeName the attribute name
     * @return the attribute name
     */
    public ModelFormFieldBuilder setAttributeName(String attributeName) {
        this.attributeName = attributeName;
        return this;
    }

    /**
     * Sets encode output.*
     * @param encodeOutput the encode output
     * @return the encode output
     */
    public ModelFormFieldBuilder setEncodeOutput(boolean encodeOutput) {
        this.encodeOutput = encodeOutput;
        return this;
    }

    /**
     * Sets entity name.*
     * @param entityName the entity name
     * @return the entity name
     */
    public ModelFormFieldBuilder setEntityName(String entityName) {
        this.entityName = entityName;
        return this;
    }

    /**
     * Sets entry name.*
     * @param entryName the entry name
     * @return the entry name
     */
    public ModelFormFieldBuilder setEntryName(String entryName) {
        this.entryAcsr = FlexibleMapAccessor.getInstance(entryName);
        return this;
    }

    /**
     * Sets event.*
     * @param event the event
     * @return the event
     */
    public ModelFormFieldBuilder setEvent(String event) {
        this.event = event;
        return this;
    }

    /**
     * Sets field info.*
     * @param fieldInfo the field info
     * @return the field info
     */
    public ModelFormFieldBuilder setFieldInfo(FieldInfo fieldInfo) {
        if (fieldInfo != null && (this.fieldInfo == null || (fieldInfo.getFieldSource() <= this.fieldInfo.getFieldSource()))) {
            this.fieldInfo = fieldInfo;
        }
        return this;
    }

    /**
     * Sets field name.*
     * @param fieldName the field name
     * @return the field name
     */
    public ModelFormFieldBuilder setFieldName(String fieldName) {
        this.fieldName = fieldName;
        return this;
    }

    /**
     * Sets field type.*
     * @param fieldType the field type
     * @return the field type
     */
    public ModelFormFieldBuilder setFieldType(String fieldType) {
        this.fieldType = fieldType;
        return this;
    }

    /**
     * Sets header link.*
     * @param headerLink the header link
     * @return the header link
     */
    public ModelFormFieldBuilder setHeaderLink(String headerLink) {
        this.headerLink = headerLink;
        return this;
    }

    /**
     * Sets header link style.*
     * @param headerLinkStyle the header link style
     * @return the header link style
     */
    public ModelFormFieldBuilder setHeaderLinkStyle(String headerLinkStyle) {
        this.headerLinkStyle = headerLinkStyle;
        return this;
    }

    /**
     * Sets id name.*
     * @param idName the id name
     * @return the id name
     */
    public ModelFormFieldBuilder setIdName(String idName) {
        this.idName = idName;
        return this;
    }

    /**
     * Sets map name.*
     * @param mapName the map name
     * @return the map name
     */
    public ModelFormFieldBuilder setMapName(String mapName) {
        this.mapAcsr = FlexibleMapAccessor.getInstance(mapName);
        return this;
    }

    /**
     * Sets model form.*
     * @param modelForm the model form
     * @return the model form
     */
    public ModelFormFieldBuilder setModelForm(ModelForm modelForm) {
        this.modelForm = modelForm;
        return this;
    }

    /**
     * Sets name.*
     * @param name the name
     * @return the name
     */
    public ModelFormFieldBuilder setName(String name) {
        this.name = name;
        return this;
    }

    /**
     * Sets parameter name.*
     * @param parameterName the parameter name
     * @return the parameter name
     */
    public ModelFormFieldBuilder setParameterName(String parameterName) {
        this.parameterName = FlexibleStringExpander.getInstance(parameterName);
        return this;
    }

    /**
     * Sets position.*
     * @param position the position
     * @return the position
     */
    public ModelFormFieldBuilder setPosition(Integer position) {
        this.position = position;
        return this;
    }

    /**
     * Sets red when.*
     * @param redWhen the red when
     * @return the red when
     */
    public ModelFormFieldBuilder setRedWhen(String redWhen) {
        this.redWhen = redWhen;
        return this;
    }

    /**
     * Sets required field.*
     * @param requiredField the required field
     * @return the required field
     */
    public ModelFormFieldBuilder setRequiredField(Boolean requiredField) {
        this.requiredField = requiredField;
        return this;
    }

    /**
     * Sets required field style.*
     * @param requiredFieldStyle the required field style
     * @return the required field style
     */
    public ModelFormFieldBuilder setRequiredFieldStyle(String requiredFieldStyle) {
        this.requiredFieldStyle = requiredFieldStyle;
        return this;
    }

    /**
     * Sets separate column.*
     * @param separateColumn the separate column
     * @return the separate column
     */
    public ModelFormFieldBuilder setSeparateColumn(boolean separateColumn) {
        this.separateColumn = separateColumn;
        return this;
    }

    /**
     * Sets service name.*
     * @param serviceName the service name
     * @return the service name
     */
    public ModelFormFieldBuilder setServiceName(String serviceName) {
        this.serviceName = serviceName;
        return this;
    }

    /**
     * Sets sort field.*
     * @param sortField the sort field
     * @return the sort field
     */
    public ModelFormFieldBuilder setSortField(Boolean sortField) {
        this.sortField = sortField;
        return this;
    }

    /**
     * Sets sort field asc style.*
     * @param sortFieldAscStyle the sort field asc style
     * @return the sort field asc style
     */
    public ModelFormFieldBuilder setSortFieldAscStyle(String sortFieldAscStyle) {
        this.sortFieldAscStyle = sortFieldAscStyle;
        return this;
    }

    /**
     * Sets sort field desc style.*
     * @param sortFieldDescStyle the sort field desc style
     * @return the sort field desc style
     */
    public ModelFormFieldBuilder setSortFieldDescStyle(String sortFieldDescStyle) {
        this.sortFieldDescStyle = sortFieldDescStyle;
        return this;
    }

    /**
     * Sets sort field help text.*
     * @param sortFieldHelpText the sort field help text
     * @return the sort field help text
     */
    public ModelFormFieldBuilder setSortFieldHelpText(String sortFieldHelpText) {
        this.sortFieldHelpText = sortFieldHelpText;
        return this;
    }

    /**
     * Sets sort field style.*
     * @param sortFieldStyle the sort field style
     * @return the sort field style
     */
    public ModelFormFieldBuilder setSortFieldStyle(String sortFieldStyle) {
        this.sortFieldStyle = sortFieldStyle;
        return this;
    }

    /**
     * Sets title.*
     * @param title the title
     * @return the title
     */
    public ModelFormFieldBuilder setTitle(String title) {
        this.title = FlexibleStringExpander.getInstance(title);
        return this;
    }

    /**
     * Sets title area style.*
     * @param titleAreaStyle the title area style
     * @return the title area style
     */
    public ModelFormFieldBuilder setTitleAreaStyle(String titleAreaStyle) {
        this.titleAreaStyle = titleAreaStyle;
        return this;
    }

    /**
     * Sets title style.*
     * @param titleStyle the title style
     * @return the title style
     */
    public ModelFormFieldBuilder setTitleStyle(String titleStyle) {
        this.titleStyle = titleStyle;
        return this;
    }

    /**
     * Sets tooltip.*
     * @param tooltip the tooltip
     * @return the tooltip
     */
    public ModelFormFieldBuilder setTooltip(String tooltip) {
        this.tooltip = FlexibleStringExpander.getInstance(tooltip);
        return this;
    }

    /**
     * Sets tooltip style.*
     * @param tooltipStyle the tooltip style
     * @return the tooltip style
     */
    public ModelFormFieldBuilder setTooltipStyle(String tooltipStyle) {
        this.tooltipStyle = tooltipStyle;
        return this;
    }

    /**
     * Sets use when.*
     * @param useWhen the use when
     * @return the use when
     */
    public ModelFormFieldBuilder setUseWhen(String useWhen) {
        this.useWhen = FlexibleStringExpander.getInstance(useWhen);
        return this;
    }

    /**
     * Sets widget area style.*
     * @param widgetAreaStyle the widget area style
     * @return the widget area style
     */
    public ModelFormFieldBuilder setWidgetAreaStyle(String widgetAreaStyle) {
        this.widgetAreaStyle = widgetAreaStyle;
        return this;
    }

    /**
     * Sets widget style.*
     * @param widgetStyle the widget style
     * @return the widget style
     */
    public ModelFormFieldBuilder setWidgetStyle(String widgetStyle) {
        this.widgetStyle = widgetStyle;
        return this;
    }

    /**
     * Sets parent form name.*
     * @param parentFormName the parent form name
     * @return the parent form name
     */
    public ModelFormFieldBuilder setParentFormName(String parentFormName) {
        this.parentFormName = parentFormName;
        return this;
    }

    /**
     * Sets tabindex.*
     * @param tabindex the tabindex
     * @return the tabindex
     */
    public ModelFormFieldBuilder setTabindex(String tabindex) {
        this.tabindex = tabindex;
        return this;
    }

    /**
     * Sets condition group.*
     * @param conditionGroup the condition group
     * @return the condition group
     */
    public ModelFormFieldBuilder setConditionGroup(String conditionGroup) {
        this.conditionGroup = conditionGroup;
        return this;
    }
}
