package org.benben.modules.business.userinfo.service;

import com.qq.connect.QQConnectException;
import org.benben.common.api.vo.RestResponseBean;
import org.benben.modules.business.userinfo.entity.UserInfo;
import com.baomidou.mybatisplus.extension.service.IService;

import javax.servlet.ServletRequest;

/**
 * @Description: 会员表
 * @author： jeecg-boot
 * @date： 2019-04-18
 * @version： V1.0
 */
public interface IUserInfoService extends IService<UserInfo> {

    public UserInfo getByUsername(String username);

    public UserInfo queryByMobile(String moblie);

    public RestResponseBean qqBinding(String openID, UserInfo userInfo);

    public UserInfo queryByWeChatOpenId(String openId);

    public Boolean bindingWeChat(String openId);

    public String getQQURL(ServletRequest request) throws QQConnectException;

    public UserInfo queryByQQOpenId(String openId);

}
