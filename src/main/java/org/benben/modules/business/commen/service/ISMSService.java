package org.benben.modules.business.commen.service;


import com.aliyuncs.dysmsapi.model.v20170525.SendSmsResponse;

/**
 * @author: WangHao
 * @date: 2019/4/10 0010
 * @description: 短信业务层
 */
public interface ISMSService {

    public String send(String mobile, String event);

    public SendSmsResponse aliSend(String mobile, String event);

    public int check(String mobile, String event, String captcha);

    public String tencentSendMess(String msg , String mobile);

    public String tencentSendMesModel(String mobile);

    public String tencentSendMesModel(String msg , String[] mobile);

    public String tencentSendMesModel(String[] mobile);

    public String sendMesVoice(String msg , String mobile);

}
