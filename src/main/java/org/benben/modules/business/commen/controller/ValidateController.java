package org.benben.modules.business.commen.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.benben.common.api.vo.RestResponseBean;
import org.benben.modules.business.commen.service.IValidateService;
import org.benben.modules.business.user.entity.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 检验接口
 */
@RestController
@RequestMapping(value = "/api/validate")
@Api(tags = {"检测接口"})
public class ValidateController {

    @Autowired
    private IValidateService validateService;

    @GetMapping(value = "/check_email_available")
    @ApiOperation(value = "检测邮箱",tags = {"检测接口"},notes = "检测邮箱")
    public RestResponseBean check_email_available(@RequestParam(name = "email")String email, @RequestParam(name="id")String id){
        String msg ="";
        int code = 0;
        try {
            User userInfo = validateService.userInfoValidate(id);
            if(null!=userInfo){
                code = email.equals(userInfo.getEmail())?0:1;
                msg = email.equals(userInfo.getEmail())?"邮箱已经被占用":"";
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
        }
        RestResponseBean RestResponseBean = new RestResponseBean(code,msg,null);
        return RestResponseBean;
    }
    @GetMapping("/check_email_exist")
    @ApiOperation(value = "检测邮箱",tags = {"检测接口"},notes = "检测邮箱")
    public RestResponseBean check_email_exist(@RequestParam(name = "mobile")String email) {
        String msg = "";
        int code = 0;
        String i = validateService.isExistEmail(email);
        code = "".equals(i)?0:1;
        msg = "".equals(i)?"邮箱不存在":"邮箱已经被占用";
        RestResponseBean RestResponseBean = new RestResponseBean(code, msg, null);
        return RestResponseBean;
    }
    @GetMapping(value = "/check_username_available")
    @ApiOperation(value = "检测用户名",tags = {"检测接口"},notes = "检测用户名")
    public RestResponseBean check_username_available(@RequestParam(name = "username")String username, @RequestParam(name="id")String id){
        String msg ="";
        int code = 0;
        try {
            User user = validateService.userInfoValidate(id);
            if(null!=user){
                code = username.equals(user.getEmail())?0:1;
                msg = username.equals(user.getEmail())?"用户名已经被占用":"";
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
        }
        RestResponseBean RestResponseBean = new RestResponseBean(code,msg,null);
        return RestResponseBean;
    }
    @GetMapping(value = "/check_mobile_available")
    @ApiOperation(value = "检测手机",tags = {"检测接口"},notes = "检测手机")
    public RestResponseBean check_mobile_available(@RequestParam(name = "mobile")String mobile, @RequestParam(name="id")String id){
        String msg ="";
        int code = 0;
        try {
            User user = validateService.userInfoValidate(id);
            if(null!=user){
                code = mobile.equals(user.getMobile())?0:1;
                msg = mobile.equals(user.getMobile())?"用户名已经被占用":"";
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
        }
        RestResponseBean RestResponseBean = new RestResponseBean(code,msg,null);
        return RestResponseBean;
    }

    @GetMapping("/check_mobile_exist")
    @ApiOperation(value = "检测手机",tags = {"检测接口"},notes = "检测手机")
    public RestResponseBean check_mobile_exist(@RequestParam(name = "mobile")String mobile) {
        String msg = "";
        int code = 0;
        String i = validateService.isExistMobile(mobile);
        code = "".equals(i)?0:1;
        msg = "".equals(i)?"邮箱不存在":"邮箱已经被占用";
        RestResponseBean RestResponseBean = new RestResponseBean(code, msg, null);
        return RestResponseBean;
    }
    @GetMapping("/check_ems_correct")
    @ApiOperation(value = "检测邮箱验证码",tags = {"检测接口"},notes = "检测邮箱验证码")
    public RestResponseBean check_ems_correct(@RequestParam(name = "email")String email, @RequestParam(name = "captcha")String captcha,
                                              @RequestParam(name = "event")String event) {
        Boolean aBoolean = validateService.captchaValidate(email,captcha,event);
        if(aBoolean){
            return new RestResponseBean(0, "验证成功", null);
        }else{
            return new RestResponseBean(1, "验证失败", null);
        }
    }


    @GetMapping("/check")
    public RestResponseBean check_ems_mobile(@RequestParam(name = "mobile")String mobile, @RequestParam(name = "captcha")String captcha,
                                             @RequestParam(name = "event")String event) {
        Boolean aBoolean = validateService.captchaValidate_mobile(mobile,captcha,event);
        if(aBoolean){
            return new RestResponseBean(0, "验证成功", null);
        }else{
            return new RestResponseBean(1, "验证失败", null);
        }
    }
}
