package org.benben.common.menu;

import lombok.Getter;

/**
 * @author: WangHao
 * @date: 2019/4/9 0009
 * @description: 短信枚举
*/

@Getter
public enum SMSResultEnum {

    SEND_SUCCESS("00000","发送成功","短信已成功发送"),
    PARAMETER_ABNORMAL("10000","参数异常","必传参数有空值()"),
    MOBILE_INCORRECT("10001","手机号格式不正确","手机号应为11位手机号"),
    TEMPLATE_NOT_EXIST("10002","模板不存在","没有申请模板,或模板未通过审核"),
    TEMPLATE_ERROR("10003","模板变量不正确","模板中含有变量,但未将变量传入,变量传值格式错误"),
    VARIABLE_SENSITIVE("10004","变量敏感字","变量中含有违法敏感词"),
    VARIABLE_MISMATCH("10005","变量名称不匹配","申请的模板中含有变量名称,变量的名称与所传变量名称不匹配"),
    SMS_TOOLONG("10006","短信长度过长","签名+模板+变量长度超过70字,超过一条短信长度,如果有超长短信需求请联系客服"),
    MOBILE_NOT_ASCRIPTION("10007","手机号查询不到归属地","所传手机号查询不到归属地"),
    PRODUCT_ERROR("10008","产品错误","系统错误,详情请联系客服"),
    PRICE_ERROR("10009","价格错误","系统错误,详情请联系客服"),
    REPEAT_CALL("10010","重复调用","由于网络原因重复调用接口"),
    SYSTEM_ERROR("10011","系统错误","详情请联系客服"),;

    private String code;

    private String message;

    private String desc;

    SMSResultEnum(String code, String message, String desc) {
        this.code = code;
        this.message = message;
        this.desc = desc;
    }

}
