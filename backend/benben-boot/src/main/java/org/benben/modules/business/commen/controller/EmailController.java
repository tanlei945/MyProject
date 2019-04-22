package org.benben.modules.business.commen.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.benben.common.api.vo.RestResponseBean;
import org.benben.modules.business.commen.service.IEmailServe;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 邮箱接口
 */
@RestController
@RequestMapping(value = "/api/ems")
@Api(tags = {"邮箱验证码接口"})
public class EmailController {

    @Autowired
    private IEmailServe emailServe;

    @GetMapping("/send")
    @ApiOperation(value = "发送验证码",tags = {"邮箱验证码接口"},notes = "发送验证码")
    public RestResponseBean offerCaptcha(@RequestParam(name = "email")String email, @RequestParam(name = "event")String event) {
        Boolean aBoolean = emailServe.offerCaptcha(email,event);
        if(aBoolean){
            return new RestResponseBean(200, "发送成功", null);
        }else{
            return new RestResponseBean(200, "发送失败", null);
        }
    }
}
