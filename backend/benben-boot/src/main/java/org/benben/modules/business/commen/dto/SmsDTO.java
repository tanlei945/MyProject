package org.benben.modules.business.commen.dto;

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
    private String mobile;

    @NotNull(message = "事件不能为空")
    @NotBlank(message = "事件不能为空")
    private String event;


    private String captcha;

}
