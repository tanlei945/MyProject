package org.benben.modules.business.user.service;

import com.qq.connect.QQConnectException;
import org.benben.common.api.vo.RestResponseBean;
import org.benben.modules.business.user.entity.User;
import com.baomidou.mybatisplus.extension.service.IService;

import javax.servlet.ServletRequest;

/**
 * @Description: 普通用户
 * @author： jeecg-boot
 * @date：   2019-04-19
 * @version： V1.0
 */
public interface IUserService extends IService<User> {

    public User getByUsername(String username);

    public User queryByMobile(String moblie);

    public RestResponseBean qqBinding(String openID, User userInfo);

    public User queryByWeChatOpenId(String openId);

    public Boolean bindingWeChat(String openId);

    public String getQQURL(ServletRequest request) throws QQConnectException;

    public User queryByQQOpenId(String openId);

}
