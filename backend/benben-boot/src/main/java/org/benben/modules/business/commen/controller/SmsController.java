package org.benben.modules.business.commen.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.apache.commons.lang.StringUtils;
import org.benben.common.api.vo.RestResponseBean;
import org.benben.common.menu.ResultEnum;
import org.benben.common.menu.SMSResultEnum;
import org.benben.common.util.RedisUtil;
import org.benben.modules.business.commen.dto.SmsDTO;
import org.benben.modules.business.commen.service.ISMSService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;


/**
 * @author: WangHao
 * @date: 2019/4/9 16:30
 * @description: 短信控制层
 */
@RestController
@RequestMapping("/api/sms/")
@Api(tags = {"短信接口"})
public class SmsController {

    @Autowired
    private RedisUtil redisUtil;

    @Autowired
    private ISMSService ismsService;

//    @GetMapping(value = "/send")
//    @ApiOperation(value = "发送验证码 ",notes = "发送验证码 ")
//    public RestResponseBean send(@RequestParam String mobile,@RequestParam String event) {
//
//        if (StringUtils.isBlank(mobile)|| StringUtils.isBlank(event)) {
//            return new RestResponseBean(ResultEnum.PARAMETER_MISSING.getValue(), ResultEnum.PARAMETER_MISSING.getDesc(), null);
//        }
//
//        String returncode =  ismsService.send(mobile,event);
//
//        if(returncode == null || StringUtils.equals(returncode,"")){
//            return new RestResponseBean(ResultEnum.SMS_SEND_FAIL.getValue(), ResultEnum.SMS_SEND_FAIL.getDesc(), null);
//        }
//
//        String message = this.getResult(returncode);
//
//        if (!StringUtils.equals(message,SMSResultEnum.SEND_SUCCESS.getMessage())) {
//            return new RestResponseBean(ResultEnum.SMS_SEND_FAIL.getValue(), message, null);
//        }
//
//        return new RestResponseBean(ResultEnum.OPERATION_SUCCESS.getValue(), "发送成功", null);
//
//    }

    /**
     * 检验验证码
     *
     * @param smsDTO
     * @param bindingResult
     * @return
     */
    @GetMapping(value = "/check")
    @ApiOperation(value = "检验短信验证码", tags = {"短信接口"},notes = "检验短信验证码")
    public RestResponseBean check(@Valid SmsDTO smsDTO, BindingResult bindingResult) {

        if (bindingResult.hasErrors() || StringUtils.isBlank(smsDTO.getCaptcha())) {
            return new RestResponseBean(ResultEnum.PARAMETER_MISSING.getValue(), ResultEnum.PARAMETER_MISSING.getDesc(), null);
        }

        int result = ismsService.check(smsDTO.getMobile(), smsDTO.getEvent(), smsDTO.getCaptcha());

        switch (result) {
            case 1:
                return new RestResponseBean(ResultEnum.SMS_CODE_OVERTIME.getValue(), ResultEnum.SMS_CODE_OVERTIME.getDesc(), null);
            case 2:
                return new RestResponseBean(ResultEnum.SMS_CODE_ERROR.getValue(), ResultEnum.SMS_CODE_ERROR.getDesc(), null);
        }

        return new RestResponseBean(ResultEnum.SMS_VALIDATE_SUCCESS.getValue(), ResultEnum.SMS_VALIDATE_SUCCESS.getDesc(), null);
    }

    /**
     * 返回短信调用错误码
     *
     * @param returncode
     * @return
     */
    protected String getResult(String returncode) {

        String message = "";

        if (StringUtils.isBlank(returncode) || returncode == null) {
            message = "发送失败";
        }

        for (SMSResultEnum smsEnum : SMSResultEnum.values()) {
            if (StringUtils.equals(smsEnum.getCode(), returncode)) {
                message = smsEnum.getMessage();
            }
        }

        return message;
    }


    @GetMapping(value = "/send")
    @ApiOperation(value = "发送验证码 ", tags = {"短信接口"},notes = "发送验证码 ")
    public RestResponseBean send(@RequestParam String mobile, @RequestParam String event) {

        if (StringUtils.isBlank(mobile) || StringUtils.isBlank(event)) {
            return new RestResponseBean(ResultEnum.PARAMETER_MISSING.getValue(), ResultEnum.PARAMETER_MISSING.getDesc(), null);
        }

        Integer code = (int) ((Math.random() * 9 + 1) * 100000);

        redisUtil.set(mobile + "," + event, String.valueOf(code), 300);

        System.out.println("验证码:" + code);

        return new RestResponseBean(ResultEnum.SMS_SEND_SUCCESS.getValue(), ResultEnum.SMS_SEND_SUCCESS.getDesc(), null);

    }


}