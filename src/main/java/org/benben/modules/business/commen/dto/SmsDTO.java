package org.benben.modules.business.commen.dto;

import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;


/**
 * @author: WangHao
 * @date: 2019/4/10 11:21
 * @description: 短信传输DTO
 */

@Data
public class SmsDTO {

    @NotNull(message = "手机号不能为空")
    @NotBlank(message = "手机号不能为空")
	@ApiModelProperty(value = "手机号",name = "mobile",required = true)
    private String mobile;

    @NotNull(message = "事件不能为空")
    @NotBlank(message = "事件不能为空")
	@ApiModelProperty(value = "短信事件",name = "event",required = true,example = "1、register2、login3、forget")
    private String event;

	@ApiModelProperty(value = "短信验证码",name = "captcha")
    private String captcha;

}
