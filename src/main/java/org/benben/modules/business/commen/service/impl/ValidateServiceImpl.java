package org.benben.modules.business.commen.service.impl;

import org.benben.modules.business.commen.mapper.ValidateMapper;
import org.benben.modules.business.commen.service.IEmailServe;
import org.benben.modules.business.commen.service.IValidateService;
import org.benben.modules.business.user.entity.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

@Service
public class ValidateServiceImpl implements IValidateService {

    @Autowired
    private ValidateMapper validateMapper;
    @Autowired
    private RedisTemplate redisTemplate;
    @Autowired
    private IEmailServe emailServe;

    @Override
    public User userInfoValidate(String id) {
        return validateMapper.userInfoValidate(id);
    }

    @Override
    public String isExistEmail(String email) {
        return validateMapper.isExistEmail(email);
    }

    @Override
    public String isExistMobile(String username) {
        return validateMapper.isExistuName(username);
    }


    @Override
    public Boolean captchaValidate(String email, String captcha, String event) {
        try {
            Object o = redisTemplate.opsForValue().get(email + ":" + event);
            return captcha.equals(o);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    @Override
    public Boolean captchaValidate_mobile(String mobile, String captcha, String event) {
        try {
            Object o = redisTemplate.opsForValue().get(mobile + ":" + event);
            return captcha.equals(o);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }


}
