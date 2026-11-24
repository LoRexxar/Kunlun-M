/*
 * Copyright (c) 2019 Of Him Code Technology Studio
 * Jpom is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * 			http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
package org.dromara.jpom.service.user;

import cn.hutool.core.collection.CollUtil;
import cn.hutool.core.comparator.CompareUtil;
import cn.hutool.core.date.SystemClock;
import cn.hutool.core.util.ObjectUtil;
import cn.hutool.core.util.RandomUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.db.Entity;
import com.alibaba.fastjson2.JSONObject;
import org.dromara.jpom.common.ServerConst;
import org.dromara.jpom.common.i18n.I18nMessageUtil;
import org.dromara.jpom.controller.user.UserWorkspaceModel;
import org.dromara.jpom.model.data.WorkspaceModel;
import org.dromara.jpom.model.dto.UserLoginDto;
import org.dromara.jpom.model.user.UserModel;
import org.dromara.jpom.service.h2db.BaseDbService;
import org.dromara.jpom.service.system.SystemParametersServer;
import org.dromara.jpom.util.JwtUtil;
import org.dromara.jpom.util.TwoFactorAuthUtils;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import java.util.List;
import java.util.stream.Collectors;

/**
 * @author bwcx_jzy
 * @since 2021/12/3
 */
@Service
public class UserService extends BaseDbService<UserModel> {
    private final SystemParametersServer systemParametersServer;
    private final UserBindWorkspaceService userBindWorkspaceService;

    public UserService(SystemParametersServer systemParametersServer,
                       UserBindWorkspaceService userBindWorkspaceService) {
        this.systemParametersServer = systemParametersServer;
        this.userBindWorkspaceService = userBindWorkspaceService;
    }

    /**
     * 是否需要初始化
     *
     * @return true 有系统管理员账号，系统可以正常使用
     */
    public boolean canUse() {
        UserModel userModel = new UserModel();
        userModel.setSystemUser(1);
        return super.exists(userModel);
    }

    @Override
    protected void fillSelectResult(UserModel data) {
        if (data == null) {
            return;
        }
        data.setSalt(null);
        data.setPassword(null);
        data.setTwoFactorAuthKey(null);
    }

    /**
     * 生成 随机盐值
     *
     * @return 随机盐值
     */
    public synchronized String generateSalt() {
        while (true) {
            String salt = RandomUtil.randomString(UserModel.SALT_LEN);
            UserModel userModel = new UserModel();
            userModel.setSalt(salt);
            boolean exists = super.exists(userModel);
            if (exists) {
                continue;
            }
            return salt + StrUtil.DASHED + SystemClock.now();
        }
    }

    /**
     * 验证用户md5
     *
     * @param userMd5 用户md5
     * @return userModel 用户对象
     */
    public UserModel checkUser(String userMd5) {
        UserModel userModel = new UserModel();
        userModel.setPassword(userMd5);
        return super.queryByBean(userModel);
    }

    /**
     * 查询用户 jwt id
     *
     * @param userModel 用户
     * @return jwt id
     */
    public UserLoginDto getUserJwtId(UserModel userModel) {
        // 判断是否禁用
        Integer status = userModel.getStatus();
        Assert.state(status == null || status == 1, ServerConst.ACCOUNT_LOCKED_TIP);
        String id = userModel.getId();
        String sql = "select password from " + this.tableName + " where id=?";
        List<Entity> query = super.query(sql, id);
        Entity first = CollUtil.getFirst(query);
        Assert.notEmpty(first, I18nMessageUtil.get("i18n.no_user_info.0355"));
        String password = (String) first.get("password");
        Assert.hasText(password, I18nMessageUtil.get("i18n.no_user_info.0355"));
        return new UserLoginDto(JwtUtil.builder(userModel, password), password);
    }

    /**
     * 当前系统中的系统管理员的数量
     *
     * @return int
     */
    public long systemUserCount() {
        UserModel userModel = new UserModel();
        userModel.setSystemUser(1);
        return super.count(super.dataBeanToEntity(userModel));
    }

    /**
     * 修改密码
     *
     * @param id     账号ID
     * @param newPwd 新密码
     */
    public void updatePwd(String id, String newPwd) {
        String salt = this.generateSalt();
        UserModel userModel = UserModel.unLock(id);
        //		userModel.setId(id);
        userModel.setSalt(salt);
        userModel.setPassword(SecureUtil.sha1(newPwd + salt));
        super.updateById(userModel);
    }

    /**
     * 用户登录
     *
     * @param name 用户名
     * @param pwd  密码
     * @return 登录
     */
    public UserModel simpleLogin(String name, String pwd) {
        UserModel userModel = super.getByKey(name, false);
        if (userModel == null) {
            return null;
        }
        String obj = SecureUtil.sha1(pwd + userModel.getSalt());
        if (StrUtil.equals(obj, userModel.getPassword())) {
            super.fillSelectResult(userModel);
            return userModel;
        }
        return null;
    }

    /**
     * 重置超级管理账号密码
     *
     * @return 新密码
     */
    public String restSuperUserPwd() {
        UserModel userModel = new UserModel();
        userModel.setParent(UserModel.SYSTEM_ADMIN);
        UserModel queryByBean = super.queryByBean(userModel);
        if (queryByBean == null) {
            return null;
        }
        String newPwd = RandomUtil.randomString(UserModel.SALT_LEN);
        this.updatePwd(queryByBean.getId(), SecureUtil.sha1(newPwd));
        return StrUtil.format(I18nMessageUtil.get("i18n.reset_super_admin_password_success.50c6"), queryByBean.getId(), newPwd);
    }

    /**
     * 关闭超级管理账号 mfa
     *
     * @return 新密码
     */
    public String closeSuperUserMfa() {
        UserModel where = new UserModel();
        where.setParent(UserModel.SYSTEM_ADMIN);
        UserModel update = new UserModel();
        update.setTwoFactorAuthKey(StrUtil.EMPTY);
        int count = super.update(super.dataBeanToEntity(update), super.dataBeanToEntity(where));
        return StrUtil.format(I18nMessageUtil.get("i18n.super_admin_mfa_verification_disabled.b97d"), count);
    }

    /**
     * 是否包含 demo 账号
     *
     * @return true
     */
    public boolean hasDemoUser() {
        UserModel userModel = new UserModel();
        userModel.setId(UserModel.DEMO_USER);
        return super.exists(userModel);
    }

    /**
     * 判断是否绑定 两步验证 mfa
     *
     * @param useId 用户ID
     * @return false 没有绑定
     */
    public boolean hasBindMfa(String useId) {
        UserModel byKey = super.getByKey(useId, false);
        Assert.notNull(byKey, I18nMessageUtil.get("i18n.user_not_exist.4892"));
        return !StrUtil.isEmpty(byKey.getTwoFactorAuthKey()) && !StrUtil.equals(byKey.getTwoFactorAuthKey(), "ignore");
    }

    /**
     * 绑定 两步验证 mfa
     *
     * @param useId 用户ID
     * @param mfa   mfa key
     */
    public void bindMfa(String useId, String mfa) {
        UserModel byKey = new UserModel();
        byKey.setId(useId);
        byKey.setTwoFactorAuthKey(mfa);
        super.updateById(byKey);
    }

    /**
     * 判断验证码是否正确
     *
     * @param userId 用户ID
     * @param code   验证码
     * @return true 正确
     */
    public boolean verifyMfaCode(String userId, String code) {
        UserModel byKey = super.getByKey(userId, false);
        Assert.notNull(byKey, I18nMessageUtil.get("i18n.user_not_exist.4892"));
        if (StrUtil.isEmpty(byKey.getTwoFactorAuthKey()) || StrUtil.equals(byKey.getTwoFactorAuthKey(), "ignore")) {
            throw new IllegalStateException(I18nMessageUtil.get("i18n.account_mfa_not_enabled.fd39"));
        }
        return TwoFactorAuthUtils.validateTFACode(byKey.getTwoFactorAuthKey(), code);
    }

    public List<UserWorkspaceModel> myWorkspace(UserModel user) {
        List<WorkspaceModel> models = userBindWorkspaceService.listUserWorkspaceInfo(user);
        Assert.notEmpty(models, I18nMessageUtil.get("i18n.account_not_bound_to_any_workspace.fd61"));
        JSONObject parametersServerConfig = systemParametersServer.getConfig("user-my-workspace-" + user.getId(), JSONObject.class);
        return models.stream()
            .map(workspaceModel -> {
                UserWorkspaceModel userWorkspaceModel = new UserWorkspaceModel();
                userWorkspaceModel.setId(workspaceModel.getId());
                userWorkspaceModel.setName(workspaceModel.getName());
                userWorkspaceModel.setGroup(workspaceModel.getGroup());
                userWorkspaceModel.setOriginalName(workspaceModel.getName());
                userWorkspaceModel.setClusterInfoId(workspaceModel.getClusterInfoId());
                Long createTimeMillis = workspaceModel.getCreateTimeMillis();
                userWorkspaceModel.setSort((int) (ObjectUtil.defaultIfNull(createTimeMillis, 0L) / 1000L));
                return userWorkspaceModel;
            })
            .peek(userWorkspaceModel -> {
                if (parametersServerConfig == null) {
                    return;
                }
                UserWorkspaceModel userConfig = parametersServerConfig.getObject(userWorkspaceModel.getId(), UserWorkspaceModel.class);
                if (userConfig == null) {
                    return;
                }
                userWorkspaceModel.setName(StrUtil.emptyToDefault(userConfig.getName(), userWorkspaceModel.getName()));
                userWorkspaceModel.setSort(ObjectUtil.defaultIfNull(userConfig.getSort(), userWorkspaceModel.getSort()));
            })
            .sorted((o1, o2) -> CompareUtil.compare(o1.getSort(), o2.getSort()))
            .collect(Collectors.toList());
    }
}
