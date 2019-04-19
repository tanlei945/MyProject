package org.benben.modules.business.user.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.qq.connect.QQConnectException;
import com.qq.connect.utils.QQConnectConfig;
import org.apache.shiro.SecurityUtils;
import org.benben.common.api.vo.RestResponseBean;
import org.benben.common.menu.ResultEnum;
import org.benben.modules.business.user.entity.User;
import org.benben.modules.business.user.mapper.UserMapper;
import org.benben.modules.business.user.service.IUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.transaction.annotation.Transactional;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;

/**
 * @Description: 普通用户
 * @author： jeecg-boot
 * @date：   2019-04-19
 * @version： V1.0
 */
@Service
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements IUserService {

    @Autowired
    private UserMapper userMapper;

    @Override
    public User getByUsername(String username) {
        QueryWrapper<User> userInfoQueryWrapper = new QueryWrapper<>();
        userInfoQueryWrapper.eq("username", username);
        User user = userMapper.selectOne(userInfoQueryWrapper);
        return user;
    }

    @Override
    public User queryByMobile(String moblie) {
        QueryWrapper<User> userInfoQueryWrapper = new QueryWrapper<>();
        userInfoQueryWrapper.eq("mobile", moblie);
        User userInfo = userMapper.selectOne(userInfoQueryWrapper);
        return userInfo;
    }

    @Override
    public RestResponseBean qqBinding(String openID, User userInfo) {

        QueryWrapper<User> queryWrapper = new QueryWrapper<>();

        queryWrapper.eq("qq_id", openID);
        User result = userMapper.selectOne(queryWrapper);
        if (result != null) {
            return new RestResponseBean(ResultEnum.USER_EXIST.getValue(), ResultEnum.USER_EXIST.getDesc(), null);
        }

        User user = (User) SecurityUtils.getSubject().getPrincipal();

        userInfo.setQqId(openID);
        int i = userMapper.updateById(userInfo);
        if (i == 0)
            return new RestResponseBean(ResultEnum.ERROR.getValue(), ResultEnum.ERROR.getDesc(), null);
        return new RestResponseBean(ResultEnum.OPERATION_SUCCESS.getValue(), ResultEnum.OPERATION_SUCCESS.getDesc(), null);

    }

    /**
     * 根据QQ openId查询UserInfo
     *
     * @param openId
     * @return
     */
    @Override
    public User queryByQQOpenId(String openId) {

        QueryWrapper<User> queryWrapper = new QueryWrapper<>();
        queryWrapper.eq("qq_id", openId);

        return userMapper.selectOne(queryWrapper);
    }


    /**
     * 根据微信openId查询UserInfo
     *
     * @param openId
     * @return
     */
    @Override
    public User queryByWeChatOpenId(String openId) {

        QueryWrapper<User> queryWrapper = new QueryWrapper<>();
        queryWrapper.eq("wx_id", openId);

        return userMapper.selectOne(queryWrapper);
    }

    /**
     * 绑定微信
     *
     * @param openId
     * @return
     */
    @Override
    @Transactional
    public Boolean bindingWeChat(String openId) {

        User user = (User) SecurityUtils.getSubject().getPrincipal();

        if (user == null) {
            return false;
        }

        user.setWxId(openId);
        userMapper.updateById(user);
        return true;
    }

    @Override
    public String getQQURL(ServletRequest request) throws QQConnectException {
        String state = request.getParameter("mobile");
//        String state = RandomStatusGenerator.getUniqueState();
        ((HttpServletRequest) request).getSession().setAttribute("qq_connect_state", state);
        String scope = QQConnectConfig.getValue("scope");
        return scope != null && !scope.equals("") ? this.getAuthorizeURL("code", state, scope) : QQConnectConfig.getValue("authorizeURL").trim() + "?client_id=" + QQConnectConfig.getValue("app_ID").trim() + "&redirect_uri=" + QQConnectConfig.getValue("redirect_URI").trim() + "&response_type=" + "code" + "&state=" + state;
    }


    public String getAuthorizeURL(String response_type, String state, String scope) throws QQConnectException {
        return QQConnectConfig.getValue("authorizeURL").trim() + "?client_id=" + QQConnectConfig.getValue("app_ID").trim() + "&redirect_uri=" + QQConnectConfig.getValue("redirect_URI").trim() + "&response_type=" + response_type + "&state=" + state + "&scope=" + scope;
    }
}
