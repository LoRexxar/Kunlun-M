/*
 * Copyright (c) 2019 Of Him Code Technology Studio
 * Jpom is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * 			http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
package org.dromara.jpom.service.h2db;

import cn.hutool.core.collection.CollUtil;
import cn.hutool.core.convert.Convert;
import cn.hutool.core.date.DatePattern;
import cn.hutool.core.date.DateTime;
import cn.hutool.core.date.DateUtil;
import cn.hutool.core.date.SystemClock;
import cn.hutool.core.map.MapUtil;
import cn.hutool.core.thread.ThreadUtil;
import cn.hutool.core.util.*;
import cn.hutool.db.Entity;
import cn.hutool.db.Page;
import cn.hutool.db.sql.Direction;
import cn.hutool.db.sql.Order;
import cn.hutool.extra.servlet.ServletUtil;
import lombok.extern.slf4j.Slf4j;
import org.dromara.jpom.common.BaseServerController;
import org.dromara.jpom.common.Const;
import org.dromara.jpom.common.i18n.I18nMessageUtil;
import org.dromara.jpom.db.BaseDbCommonService;
import org.dromara.jpom.db.DbExtConfig;
import org.dromara.jpom.dialect.DialectUtil;
import org.dromara.jpom.model.BaseDbModel;
import org.dromara.jpom.model.BaseUserModifyDbModel;
import org.dromara.jpom.model.PageResultDto;
import org.dromara.jpom.model.user.UserModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import java.util.*;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * 数据库操作 通用 serve
 *
 * @author bwcx_jzy
 * @since 2021/8/13
 */
@Slf4j
public abstract class BaseDbService<T extends BaseDbModel> extends BaseDbCommonService<T> {

    @Autowired
    @Lazy
    private DbExtConfig extConfig;
    /**
     * 旧版本分组
     */
    private final boolean canGroup;
    /**
     * 新版本分组字段
     */
    private final boolean canGroupName;
    /**
     * 默认排序规则
     */
    private static final Order[] DEFAULT_ORDERS = new Order[]{
        new Order("createTimeMillis", Direction.DESC),
        new Order("modifyTimeMillis", Direction.DESC),
        new Order("id", Direction.DESC)
    };

    public BaseDbService() {
        super();
        this.canGroup = ReflectUtil.hasField(this.tClass, "group");
        this.canGroupName = ReflectUtil.hasField(this.tClass, "groupName");
    }

    public boolean isCanGroup() {
        return canGroup;
    }

    /**
     * load date group by group name
     *
     * @return list
     */
    public List<String> listGroup() {
        String group = DialectUtil.wrapField("group");
        String sql = String.format("select %s from %s group by %s", group, getTableName(), group);
        return this.listGroupByName(sql, "group");
    }


    /**
     * load date group by group name
     *
     * @return list
     */
    public List<String> listGroupName() {
        String sql = "select groupName from " + this.getTableName() + " group by groupName";
        return this.listGroupByName(sql, "groupName");
    }

    /**
     * 获取分组字段
     *
     * @param sql    sql 预计
     * @param params 参数
     * @return list
     */
    public List<String> listGroupByName(String sql, String fieldName, Object... params) {
        Assert.state(this.canGroup || this.canGroupName, I18nMessageUtil.get("i18n.data_table_not_supported_for_grouping.6678"));
        List<Entity> list = super.query(sql, params);
        String unWrapField = DialectUtil.unWrapField(fieldName);
        // 筛选字段
        return list.stream()
            .flatMap(entity -> {
                Object obj = entity.get(unWrapField);
                if (obj == null) {
                    return null;
                }
                return Stream.of(String.valueOf(obj));
            })
            .filter(Objects::nonNull)
            .distinct()
            .collect(Collectors.toList());
    }


    /**
     * 恢复字段
     */
    public void repairGroupFiled() {
        Assert.state(this.canGroup, I18nMessageUtil.get("i18n.data_table_not_supported_for_grouping.6678"));
        String group = DialectUtil.wrapField("group");
        String sql = String.format("update %s set %s =? where %s is null or %s = ''", getTableName(), group, group, group);
        super.execute(sql, Const.DEFAULT_GROUP_NAME.get());
    }

    public int insert(T t) {
        this.fillInsert(t);
        int count = super.insertDb(t);
        this.executeClear();
        return count;
    }

    /**
     * 先尝试 更新，更新失败插入
     *
     * @param t 数据
     */
    public void upsert(T t) {
        int update = this.updateById(t);
        if (update <= 0) {
            this.insert(t);
        }
    }

    public void insert(Collection<T> t) {
        // def create time
        t.forEach(this::fillInsert);
        super.insertDb(t);
        this.executeClear();
    }

    /**
     * 插入数据填充
     *
     * @param t 数据
     */
    protected void fillInsert(T t) {
        // def create time
        t.setCreateTimeMillis(ObjectUtil.defaultIfNull(t.getCreateTimeMillis(), SystemClock.now()));
        t.setId(StrUtil.emptyToDefault(t.getId(), IdUtil.fastSimpleUUID()));
        if (t instanceof BaseUserModifyDbModel) {
            UserModel userModel = BaseServerController.getUserModel();
            userModel = userModel == null ? BaseServerController.getUserByThreadLocal() : userModel;
            // 获取数据修改人
            BaseUserModifyDbModel modifyDbModel = (BaseUserModifyDbModel) t;
            if (userModel != null) {
                modifyDbModel.setModifyUser(ObjectUtil.defaultIfNull(modifyDbModel.getModifyUser(), userModel.getId()));
                modifyDbModel.setCreateUser(ObjectUtil.defaultIfNull(modifyDbModel.getCreateUser(), userModel.getId()));
            }
        }
    }

    /**
     * update by id with data
     *
     * @param info          data
     * @param whereConsumer 查询条件回调
     * @return 影响的行数
     */
    public int updateById(T info, Consumer<Entity> whereConsumer) {
        // check id
        String id = info.getId();
        Assert.hasText(id, I18nMessageUtil.get("i18n.cannot_execute_error.4c29"));
        // def modify time
        info.setModifyTimeMillis(ObjectUtil.defaultIfNull(info.getModifyTimeMillis(), SystemClock.now()));

        // fill modify user
        if (info instanceof BaseUserModifyDbModel) {
            BaseUserModifyDbModel modifyDbModel = (BaseUserModifyDbModel) info;
            UserModel userModel = BaseServerController.getUserModel();
            if (userModel != null) {
                modifyDbModel.setModifyUser(ObjectUtil.defaultIfNull(modifyDbModel.getModifyUser(), userModel.getId()));
            }
        }
        //
        Entity entity = this.dataBeanToEntity(info);
        //
        this.removeUpdate(entity);
        //
        Entity where = new Entity();
        where.set(ID_STR, id);
        if (whereConsumer != null) {
            whereConsumer.accept(where);
        }
        return super.updateDb(entity, where);
    }

    private void removeUpdate(Entity entity) {
        for (String s : new String[]{ID_STR, "createTimeMillis", "createUser"}) {
            entity.remove(DialectUtil.wrapField(s));
            entity.remove(s);
        }
    }


    /**
     * 根据主键查询实体
     *
     * @param keyValue 主键值
     * @return 数据
     */
    public T getByKey(String keyValue) {
        return this.getByKey(keyValue, true);
    }

    /**
     * 根据主键查询实体
     *
     * @param keyValue 主键值
     * @return 数据
     */
    public List<T> getByKey(Collection<String> keyValue) {
        return this.getByKey(keyValue, true, null);
    }

    /**
     * 根据主键查询实体
     *
     * @param keyValue 主键值
     * @return 数据
     */
    public T getByKey(String keyValue, boolean fill) {
        return this.getByKey(keyValue, fill, null);
    }

    /**
     * update by id with data
     *
     * @param info data
     * @return 影响的行数
     */
    public int updateById(T info) {
        return this.updateById(info, null);
    }

    public int update(Entity entity, Entity where) {
        this.removeUpdate(entity);
        return super.updateDb(entity, where);
    }

    /**
     * 同步 bean 删除
     *
     * @param info bean
     * @return 影响行数
     */
    public int delByBean(T info) {
        Entity where = this.dataBeanToEntity(info);
        Assert.state(!where.isEmpty(), I18nMessageUtil.get("i18n.no_parameters_added_with_minus_two.a7cf"));
        return this.del(where);
    }


    /**
     * 根据主键删除
     *
     * @param keyValue 主键值
     * @return 影响行数
     */
    public int delByKey(String keyValue) {
        if (StrUtil.isEmpty(keyValue)) {
            return 0;
        }
        return this.delByKey(keyValue, null);
    }

    /**
     * 根据主键删除
     *
     * @param ids 主键值
     * @return 影响行数
     */
    public int delByKey(List<String> ids) {
        if (CollUtil.isEmpty(ids)) {
            return 0;
        }
        return this.delByKey(ids, null);
    }

    /**
     * 根据主键生成
     *
     * @param keyValue 主键值
     * @param consumer 回调
     * @return 影响行数
     */
    public int delByKey(Object keyValue, Consumer<Entity> consumer) {
        Entity where = new Entity(tableName);
        if (keyValue != null) {
            where.set(ID_STR, keyValue);
        }
        if (consumer != null) {
            consumer.accept(where);
        }
        Assert.state(!where.isEmpty(), I18nMessageUtil.get("i18n.no_parameters_added_with_minus_one.e47d"));
        return del(where);
    }

    /**
     * 判断是否存在
     *
     * @param data 实体
     * @return true 存在
     */
    public boolean exists(T data) {
        Entity entity = this.dataBeanToEntity(data);
        return this.exists(entity);
    }

    /**
     * 判断是否存在
     *
     * @param dataId 数据id
     * @return true 存在
     */
    public boolean exists(String dataId) {
        Entity entity = Entity.create();
        entity.set(ID_STR, dataId);
        long count = this.count(entity);
        return count > 0;
    }

    /**
     * 判断是否存在
     *
     * @param where 条件
     * @return true 存在
     */
    public boolean exists(Entity where) {
        long count = this.count(where);
        return count > 0;
    }

    /**
     * 查询一个
     *
     * @param where 条件
     * @return Entity
     */
    public Entity query(Entity where) {
        List<Entity> entities = this.queryList(where);
        return CollUtil.getFirst(entities);
    }

    /**
     * 查询 list
     *
     * @param where 条件
     * @return data
     */
    public List<T> listByEntity(Entity where) {
        List<Entity> entity = this.queryList(where);
        return this.entityToBeanList(entity);
    }

    /**
     * 查询 list
     *
     * @param where 条件
     * @param fill  是否填充
     * @return data
     */
    public List<T> listByEntity(Entity where, boolean fill) {
        List<Entity> entity = this.queryList(where);
        return this.entityToBeanList(entity, fill);
    }

    /**
     * 查询列表
     *
     * @param data   数据
     * @param count  查询数量
     * @param orders 排序
     * @return List
     */
    public List<T> queryList(T data, int count, Order... orders) {
        Entity where = this.dataBeanToEntity(data);
        return this.queryList(where, count, orders);
    }

    /**
     * 查询列表
     *
     * @param where  条件
     * @param count  查询数量
     * @param orders 排序
     * @return List
     */
    public List<T> queryList(Entity where, int count, Order... orders) {
        Page page = new Page(1, count);
        page.addOrder(orders);
        PageResultDto<T> tPageResultDto = this.listPage(where, page);
        return tPageResultDto.getResult();
    }


    /**
     * 分页查询
     *
     * @param where 条件
     * @param page  分页
     * @return 结果
     */
    public PageResultDto<T> listPage(Entity where, Page page) {
        return this.listPage(where, page, true);
    }

    /**
     * 分页查询
     *
     * @param where 条件
     * @param page  分页
     * @return 结果
     */
    public List<T> listPageOnlyResult(Entity where, Page page) {
        PageResultDto<T> pageResultDto = this.listPage(where, page);
        return pageResultDto.getResult();
    }

    /**
     * sql 查询 list
     *
     * @param sql    sql 语句
     * @param params 参数
     * @return list
     */
    public List<T> queryList(String sql, Object... params) {
        List<Entity> query = this.query(sql, params);
        return this.entityToBeanList(query);
    }

    /**
     * 查询实体对象
     *
     * @param data 实体
     * @return data
     */
    public List<T> listByBean(T data) {
        return this.listByBean(data, true);
    }

    /**
     * 查询实体对象
     *
     * @param data 实体
     * @return data
     */
    public List<T> listByBean(T data, boolean fill) {
        Entity where = this.dataBeanToEntity(data);
        List<Entity> entitys = this.queryList(where);
        return this.entityToBeanList(entitys, fill);
    }

    /**
     * 查询实体对象
     *
     * @param data 实体
     * @return data
     */
    public T queryByBean(T data) {
        Entity where = this.dataBeanToEntity(data);
        Entity entity = this.query(where);
        return this.entityToBean(entity, true);
    }

    public List<T> list() {
        return this.list(true);
    }

    public List<T> list(boolean fill) {
        return this.listByBean(ReflectUtil.newInstance(this.tClass), fill);
    }

    public long count() {
        return super.count(Entity.create());
    }

    public long count(T data) {
        return super.count(this.dataBeanToEntity(data));
    }

    /**
     * 通用的分页查询, 使用该方法查询，数据库表字段不能包含 "page", "limit", "order_field", "order", "total"
     * <p>
     * page=1&limit=10&order=ascend&order_field=name
     *
     * @param request 请求对象
     * @return page
     */
    public PageResultDto<T> listPage(HttpServletRequest request) {
        return this.listPage(request, true);
    }

    /**
     * 通用的分页查询, 使用该方法查询，数据库表字段不能包含 "page", "limit", "order_field", "order", "total"
     * <p>
     * page=1&limit=10&order=ascend&order_field=name
     *
     * @param request 请求对象
     * @return page
     */
    public PageResultDto<T> listPage(HttpServletRequest request, boolean fill) {
        Map<String, String> paramMap = ServletUtil.getParamMap(request);
        return this.listPage(paramMap, fill);
    }

    /**
     * 转换为 page 对象
     *
     * @param paramMap 请求参数
     * @return page
     */
    public Page parsePage(Map<String, String> paramMap) {
        int page = Convert.toInt(paramMap.get("page"), 1);
        int limit = Convert.toInt(paramMap.get("limit"), 10);
        Assert.state(page > 0, "page value error");
        Assert.state(limit > 0 && limit < 200, "limit value error");
        // 移除 默认字段
        MapUtil.removeAny(paramMap, "page", "limit", "order_field", "order", "total");
        //
        return new Page(page, limit);
    }

    /**
     * 通用的分页查询, 使用该方法查询，数据库表字段不能包含 "page", "limit", "order_field", "order", "total"
     * <p>
     * page=1&limit=10&order=ascend&order_field=name
     *
     * @param paramMap 请求参数
     * @return page
     */
    public PageResultDto<T> listPage(Map<String, String> paramMap) {
        return this.listPage(paramMap, true);
    }

    /**
     * 通用的分页查询, 使用该方法查询，数据库表字段不能包含 "page", "limit", "order_field", "order", "total"
     * <p>
     * page=1&limit=10&order=ascend&order_field=name
     *
     * @param paramMap 请求参数
     * @return page
     */
    public PageResultDto<T> listPage(Map<String, String> paramMap, boolean fill) {
        String orderField = paramMap.get("order_field");
        String order = paramMap.get("order");
        //
        Page pageReq = this.parsePage(paramMap);
        Entity where = Entity.create();
        List<String> ignoreField = new ArrayList<>(10);
        // 查询条件
        for (Map.Entry<String, String> stringStringEntry : paramMap.entrySet()) {
            String key = stringStringEntry.getKey();
            String value = stringStringEntry.getValue();
            if (StrUtil.isEmpty(value)) {
                continue;
            }
            key = StrUtil.removeAll(key, "%");
            if (StrUtil.startWith(stringStringEntry.getKey(), "%") && StrUtil.endWith(stringStringEntry.getKey(), "%")) {
                where.set(DialectUtil.wrapField(key), StrUtil.format(" like '%{}%'", value));
            } else if (StrUtil.endWith(stringStringEntry.getKey(), "%")) {
                where.set(DialectUtil.wrapField(key), StrUtil.format(" like '{}%'", value));
            } else if (StrUtil.startWith(stringStringEntry.getKey(), "%")) {
                where.set(DialectUtil.wrapField(key), StrUtil.format(" like '%{}'", value));
            } else if (StrUtil.containsIgnoreCase(key, "time") && StrUtil.contains(value, "~")) {
                // 时间筛选
                String[] val = StrUtil.splitToArray(value, "~");
                if (val.length == 2) {
                    DateTime startDateTime = DateUtil.parse(val[0], DatePattern.NORM_DATETIME_FORMAT);
                    where.set(key, ">= " + startDateTime.getTime());

                    DateTime endDateTime = DateUtil.parse(val[1], DatePattern.NORM_DATETIME_FORMAT);
                    if (startDateTime.equals(endDateTime)) {
                        endDateTime = DateUtil.endOfDay(endDateTime);
                    }
                    // 防止字段重复
                    where.set(key + " ", "<= " + endDateTime.getTime());
                }
            } else if (StrUtil.containsIgnoreCase(key, "time")) {
                // 时间筛选
                String timeKey = StrUtil.removeAny(key, "[0]", "[1]");
                if (ignoreField.contains(timeKey)) {
                    continue;
                }
                String startTime = paramMap.get(timeKey + "[0]");
                String endTime = paramMap.get(timeKey + "[1]");
                if (StrUtil.isAllNotEmpty(startTime, endTime)) {
                    DateTime startDateTime = DateUtil.parse(startTime, DatePattern.NORM_DATETIME_FORMAT);
                    where.set(timeKey, ">= " + startDateTime.getTime());

                    DateTime endDateTime = DateUtil.parse(endTime, DatePattern.NORM_DATETIME_FORMAT);
                    if (startDateTime.equals(endDateTime)) {
                        endDateTime = DateUtil.endOfDay(endDateTime);
                    }
                    // 防止字段重复
                    where.set(timeKey + " ", "<= " + endDateTime.getTime());
                }
                ignoreField.add(timeKey);
            } else if (StrUtil.endWith(key, ":in")) {
                String inKey = StrUtil.removeSuffix(key, ":in");
                where.set(DialectUtil.wrapField(inKey), StrUtil.split(value, StrUtil.COMMA));
            } else {
                where.set(DialectUtil.wrapField(key), value);
            }
        }
        // 排序
        if (StrUtil.isNotEmpty(orderField)) {
            orderField = StrUtil.removeAll(orderField, "%");
            pageReq.addOrder(new Order(DialectUtil.wrapField(orderField), StrUtil.equalsIgnoreCase(order, "ascend") ? Direction.ASC : Direction.DESC));
        }
        return this.listPage(where, pageReq, fill);
    }

    public PageResultDto<T> listPage(Entity where, Page page, boolean fill) {
        if (ArrayUtil.isEmpty(page.getOrders())) {
            page.addOrder(this.defaultOrders());
        }
        return this.listPageDb(where, page, fill);
    }

    public Order[] defaultOrders() {
        return DEFAULT_ORDERS;
    }

    /**
     * 多个 id 查询数据
     *
     * @param ids ids
     * @return list
     */
    public List<T> listById(Collection<String> ids) {
        return this.listById(ids, null);
    }

    /**
     * 多个 id 查询数据
     *
     * @param ids ids
     * @return list
     */
    public List<T> listById(Collection<String> ids, boolean fill) {
        return this.listById(ids, null, fill);
    }

    /**
     * 多个 id 查询数据
     *
     * @param ids ids
     * @return list
     */
    public List<T> listById(Collection<String> ids, Consumer<Entity> consumer) {
        return this.listById(ids, consumer, true);
    }

    /**
     * 多个 id 查询数据
     *
     * @param ids ids
     * @return list
     */
    public List<T> listById(Collection<String> ids, Consumer<Entity> consumer, boolean fill) {
        if (CollUtil.isEmpty(ids)) {
            return null;
        }
        Entity entity = Entity.create();
        entity.set(ID_STR, ids);
        if (consumer != null) {
            consumer.accept(entity);
        }
        List<Entity> entities = super.queryList(entity);
        return this.entityToBeanList(entities, fill);
    }

    /**
     * 执行清理
     */
    private void executeClear() {
        int h2DbLogStorageCount = extConfig.getLogStorageCount();
        if (h2DbLogStorageCount <= 0) {
            return;
        }
        this.executeClearImpl(h2DbLogStorageCount);
    }

    /**
     * 清理分发实现
     *
     * @param h2DbLogStorageCount 保留数量
     */
    protected void executeClearImpl(int h2DbLogStorageCount) {
        String[] strings = this.clearTimeColumns();
        for (String timeColumn : strings) {
            this.autoClear(timeColumn, h2DbLogStorageCount, time -> {
                Entity entity = Entity.create(super.getTableName());
                entity.set(timeColumn, "< " + time);
                int count = super.del(entity);
                if (count > 0) {
                    log.debug(I18nMessageUtil.get("i18n.cleaned_data.0e9d"), super.getTableName(), count);
                }
            });
        }
    }

    /**
     * 安装时间自动清理数据对字段
     *
     * @return 数组
     */
    protected String[] clearTimeColumns() {
        return new String[]{};
    }

    /**
     * 自动清理数据接口
     *
     * @param timeColumn 时间字段
     * @param maxCount   最大数量
     * @param consumer   查询出超过范围的时间回调
     */
    protected void autoClear(String timeColumn, int maxCount, Consumer<Long> consumer) {
        if (maxCount <= 0) {
            return;
        }
        ThreadUtil.execute(() -> {
            long timeValue = this.getLastTimeValue(timeColumn, maxCount, null);
            if (timeValue <= 0) {
                return;
            }
            consumer.accept(timeValue);
        });
    }

    /**
     * 查询指定字段降序 指定条数对最后一个值
     *
     * @param timeColumn 时间字段
     * @param maxCount   最大数量
     * @param whereCon   添加查询条件回调
     * @return 时间
     */
    protected long getLastTimeValue(String timeColumn, int maxCount, Consumer<Entity> whereCon) {
        Entity entity = Entity.create(super.getTableName());
        if (whereCon != null) {
            // 条件
            whereCon.accept(entity);
        }
        Page page = new Page(maxCount, 1);
        page.addOrder(new Order(timeColumn, Direction.DESC));
        PageResultDto<T> pageResult;
        try {
            pageResult = this.listPage(entity, page);
        } catch (java.lang.IllegalStateException illegalStateException) {
            return 0L;
        } catch (Exception e) {
            log.error(I18nMessageUtil.get("i18n.query_data_error.45e7"), e);
            return 0L;
        }
        if (pageResult.isEmpty()) {
            return 0L;
        }
        T entity1 = pageResult.get(0);
        Object fieldValue = ReflectUtil.getFieldValue(entity1, timeColumn);
        return Convert.toLong(fieldValue, 0L);
    }

    /**
     * 自动清理数据接口
     *
     * @param timeClo   时间字段
     * @param maxCount  最大数量
     * @param predicate 查询出超过范围的时间,回调
     */
    protected void autoLoopClear(String timeClo, int maxCount, Consumer<Entity> whereCon, Predicate<T> predicate) {
        if (maxCount <= 0) {
            return;
        }
        ThreadUtil.execute(() -> {
            Entity entity = Entity.create(super.getTableName());
            long timeValue = this.getLastTimeValue(timeClo, maxCount, whereCon);
            if (timeValue <= 0) {
                return;
            }
            if (whereCon != null) {
                // 条件
                whereCon.accept(entity);
            }
            entity.set(timeClo, "< " + timeValue);
            while (true) {
                Page page = new Page(1, 50);
                page.addOrder(new Order(timeClo, Direction.DESC));
                PageResultDto<T> pageResult = this.listPage(entity, page);
                if (pageResult.isEmpty()) {
                    return;
                }
//                pageResult.each(consumer);
                List<String> ids = pageResult.getResult().stream().filter(predicate).map(BaseDbModel::getId).collect(Collectors.toList());
                this.delByKey(ids, null);
            }
        });
    }

    /**
     * 根据 节点和数据ID查询数据
     *
     * @param nodeId 节点ID
     * @param dataId 数据ID
     * @return data
     */
    public T getData(String nodeId, String dataId) {
        return this.getByKey(dataId);
    }
}
