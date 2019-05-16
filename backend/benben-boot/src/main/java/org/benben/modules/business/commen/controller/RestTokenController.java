package org.benben.modules.business.commen.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.benben.common.api.vo.RestResponseBean;
import org.benben.modules.business.commen.service.ITokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/token/")
@Api(tags = {"token接口"})
public class RestTokenController {
    @Autowired
    private ITokenService tokenService;

    @GetMapping("/check")
    @ApiOperation(value = "验证token", tags = {"token接口"},notes = "验证token")
    public RestResponseBean check(String key) {
        RestResponseBean check = tokenService.check(key);
        return check;
    }

    @GetMapping("/refresh")
    @ApiOperation(value = "刷新token", tags = {"token接口"},notes = "刷新token")
    public String refresh(String key) {
        String refresh = tokenService.refresh(key);
        return refresh;
    }

}
