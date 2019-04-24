package org.benben.common.menu;

/**
 * @author: WangHao
 * @date: 2019/4/24 16:12
 * @description: 短信类型枚举
 */

public enum SMSTypeEnum {

    Register("注册验证"), Login("登录验证"), Change("变更验证"), Id("身份验证"), Active("活动验证"), Pass("变更验证");
    private String title;

    private SMSTypeEnum(String title) {
        this.title = title;
    }

    public static SMSTypeEnum valueof(int index) {
        return SMSTypeEnum.values()[index];
    }

    public String getTitle() {
        return title;
    }
}
