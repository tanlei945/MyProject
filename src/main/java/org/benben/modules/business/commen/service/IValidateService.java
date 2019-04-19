package org.benben.modules.business.commen.service;


import org.benben.modules.business.user.entity.User;

/**
 * @Description: 检验业务层代码
 * @author： jeecg-boot
 * @date： 2019-04-08
 * @version： V1.0
 */
public interface IValidateService {

    User userInfoValidate(String id);

    String isExistEmail(String email);

    String isExistMobile(String mobile);

    Boolean captchaValidate(String email, String captcha, String event);

    Boolean captchaValidate_mobile(String mobile, String captcha, String event);
}
