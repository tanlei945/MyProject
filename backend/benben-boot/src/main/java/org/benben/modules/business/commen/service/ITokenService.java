package org.benben.modules.business.commen.service;


import org.benben.common.api.vo.RestResponseBean;

public interface ITokenService {

    public RestResponseBean check(String key);

    public String refresh(String key);
}
