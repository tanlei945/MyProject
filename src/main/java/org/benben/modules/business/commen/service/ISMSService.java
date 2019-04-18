package org.benben.modules.business.commen.service;


/**
 * @author: WangHao
 * @date: 2019/4/10 0010
 * @description: 短信业务层
*/
public interface ISMSService {

    public String send(String mobile, String event);

    public int check(String mobile, String event, String captcha);

}
