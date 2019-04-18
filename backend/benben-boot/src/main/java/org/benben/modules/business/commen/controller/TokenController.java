package org.benben.modules.business.commen.controller;

import org.benben.common.api.vo.RestResponseBean;
import org.benben.modules.business.commen.service.ITokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/token/")
public class TokenController {
    @Autowired
    private ITokenService tokenService;

    @GetMapping("/check")
    public RestResponseBean check(String key) {
        RestResponseBean check = tokenService.check(key);
        return check;
    }

    @GetMapping("/refresh")
    public String refresh(String key) {
        String refresh = tokenService.refresh(key);
        return refresh;
    }

}
