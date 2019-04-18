package org.benben.modules.business.userinfo.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.qq.connect.QQConnectException;
import com.qq.connect.utils.QQConnectConfig;
import org.apache.shiro.SecurityUtils;
import org.benben.common.api.vo.RestResponseBean;
import org.benben.common.menu.ResultEnum;
import org.benben.modules.business.userinfo.entity.UserInfo;
import org.benben.modules.business.userinfo.mapper.UserInfoMapper;
import org.benben.modules.business.userinfo.service.IUserInfoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.transaction.annotation.Transactional;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;

/**
 * @Description: 会员表
 * @author： jeecg-boot
 * @date： 2019-04-18
 * @version： V1.0
 */
@Service
public class UserInfoServiceImpl extends ServiceImpl<UserInfoMapper, UserInfo> implements IUserInfoService {

    @Autowired
    private UserInfoMapper userInfoMapper;

    @Override
    public UserInfo getByUsername(String username) {
        QueryWrapper<UserInfo> userInfoQueryWrapper = new QueryWrapper<>();
        userInfoQueryWrapper.eq("username", username);
        UserInfo userInfo = userInfoMapper.selectOne(userInfoQueryWrapper);
        return userInfo;
    }

    @Override
    public UserInfo queryByMobile(String moblie) {
        QueryWrapper<UserInfo> userInfoQueryWrapper = new QueryWrapper<>();
        userInfoQueryWrapper.eq("mobile", moblie);
        UserInfo userInfo = userInfoMapper.selectOne(userInfoQueryWrapper);
        return userInfo;
    }

    @Override
    public RestResponseBean qqBinding(String openID, UserInfo userInfo) {

        QueryWrapper<UserInfo> queryWrapper = new QueryWrapper<>();

        queryWrapper.eq("qq_id", openID);
        UserInfo result = userInfoMapper.selectOne(queryWrapper);
        if (result != null) {
            return new RestResponseBean(ResultEnum.USER_EXIST.getValue(), ResultEnum.USER_EXIST.getDesc(), null);
        }

        UserInfo user = (UserInfo) SecurityUtils.getSubject().getPrincipal();

        userInfo.setQqId(openID);
        int i = userInfoMapper.updateById(userInfo);
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
    public UserInfo queryByQQOpenId(String openId) {

        QueryWrapper<UserInfo> queryWrapper = new QueryWrapper<>();
        queryWrapper.eq("qq_id", openId);

        return userInfoMapper.selectOne(queryWrapper);
    }


    /**
     * 根据微信openId查询UserInfo
     *
     * @param openId
     * @return
     */
    @Override
    public UserInfo queryByWeChatOpenId(String openId) {

        QueryWrapper<UserInfo> queryWrapper = new QueryWrapper<>();
        queryWrapper.eq("wx_id", openId);

        return userInfoMapper.selectOne(queryWrapper);
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

        UserInfo userInfo = (UserInfo) SecurityUtils.getSubject().getPrincipal();

        if (userInfo == null) {
            return false;
        }

        userInfo.setWxId(openId);
        userInfoMapper.updateById(userInfo);
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
