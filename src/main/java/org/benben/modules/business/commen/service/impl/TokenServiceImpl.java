package org.benben.modules.business.commen.service.impl;

import org.benben.common.api.vo.RestResponseBean;
import org.benben.common.menu.ResultEnum;
import org.benben.common.util.RedisUtil;
import org.benben.modules.business.commen.service.ITokenService;
import org.benben.modules.shiro.authc.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class TokenServiceImpl implements ITokenService {
    @Autowired
    private RedisUtil redisUtil;

    @Override
    public RestResponseBean check(String key) {
        RestResponseBean restResponseBean;
        if (key == null || key == "") {
            restResponseBean = new RestResponseBean(ResultEnum.PARAMETER_MISSING.getValue(), ResultEnum.TOKEN_OVERDUE.getDesc(), null);
            return restResponseBean;
        }
        boolean b = redisUtil.hasKey(key);
        if (!b) {
            restResponseBean = new RestResponseBean(ResultEnum.TOKEN_OVERDUE.getValue(), ResultEnum.TOKEN_OVERDUE.getDesc(), null);
            return restResponseBean;
        }
        restResponseBean = new RestResponseBean(ResultEnum.TOKEN_NOT_OVERDUE.getValue(), ResultEnum.TOKEN_NOT_OVERDUE.getDesc(), null);

        return restResponseBean;
    }

    @Override
    public String refresh(String key) {
        redisUtil.expire(key, JwtUtil.APP_EXPIRE_TIME);
        String result = redisUtil.get(key).toString();

        return result;
    }
}
