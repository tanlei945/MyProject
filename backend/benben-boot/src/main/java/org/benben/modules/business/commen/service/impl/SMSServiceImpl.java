package org.benben.modules.business.commen.service.impl;

import com.alibaba.fastjson.JSONException;
import com.alibaba.fastjson.JSONObject;
import com.aliyuncs.dysmsapi.model.v20170525.SendSmsResponse;
import com.github.qcloudsms.*;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.SimpleHttpConnectionManager;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.params.HttpMethodParams;
import org.apache.commons.lang.StringUtils;
import org.benben.common.menu.SMSResultEnum;
import org.benben.common.util.DateUtils;
import org.benben.common.util.RedisUtil;
import org.benben.common.util.aliyun.AliMessageSend;
import org.benben.modules.business.commen.service.ISMSService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.github.qcloudsms.httpclient.HTTPException;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * @author: WangHao
 * @date: 2019/4/10 10:00
 * @description: 短信业务层
 */
@Service
@Slf4j
public class SMSServiceImpl implements ISMSService {

    @Value("${sms.host}")
    private String host;
    @Value("${sms.appcode}")
    private String appcode;
    @Value("${tencentsms.appId}")
    private int tencentAppId;
    @Value("${tencentsms.appkey}")
    private String tencentAppkey;
    @Value("${tencentsms.templateId}")
    private int tencentTemplateId;
    @Value("${tencentsms.smsSign}")
    private String tencentSmsSign;

    @Autowired
    private RedisUtil redisUtil;

    /**
     * 短信发送
     *
     * @param mobile 手机号码
     * @param event  事件
     * @return
     */
    @Override
    public String send(String mobile, String event) {

        HttpClient httpclient = null;
        PostMethod postMethod = null;

        String returncode = "";

        Integer code = (int) ((Math.random() * 9 + 1) * 100000);

        try {
            //创建连接
            httpclient = new HttpClient();
            postMethod = new PostMethod(host);
            //设置编码方式
            postMethod.getParams().setParameter(HttpMethodParams.HTTP_CONTENT_CHARSET, "UTF-8");
            postMethod.setRequestHeader("Authorization", "APPCODE " + appcode);
            //添加参数
            postMethod.addParameter("phone", mobile);
            postMethod.addParameter("variable", "num:" + code + ",money:888");
            postMethod.addParameter("templateId", "TP1711063");
            //执行请求
            httpclient.executeMethod(postMethod);
            //返回信息
            String result = new String(postMethod.getResponseBody(), "UTF-8");
            System.out.println("短信返回code" + result);
            if (StringUtils.isNotBlank(result)) {
                JSONObject object = JSONObject.parseObject(result);
                returncode = object.getString("return_code");
            }


        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            //关闭连接,释放资源
            postMethod.releaseConnection();
            ((SimpleHttpConnectionManager) httpclient.getHttpConnectionManager()).shutdown();
        }

        if (StringUtils.equals(returncode, SMSResultEnum.SEND_SUCCESS.getCode())) {
            //存入redis
            redisUtil.set(mobile + "," + event, String.valueOf(code), 300);
        }
        System.out.println("验证码:" + code);

        return returncode;
    }

    /**
     * 短信发送公用模板
     * @param mobile
     * @param event
     * @return
     * @throws Exception
     */
    @Override
    public SendSmsResponse aliSend(String mobile, String event) {

        log.error("请求短信serve" + DateUtils.now());

        SendSmsResponse sendSmsResponse = new SendSmsResponse();

        Map<String, Integer> map = new HashMap<>();

        if (StringUtils.isNotBlank(event)) {   //发起短信验证

            Integer code = (int) ((Math.random() * 9 + 1) * 100000);

            map.put("code", code);

//            log.error("调用redis,Set值"+System.currentTimeMillis());
            log.error("调用redis,Set值" + mobile + event + "code: " + code.toString() + "  时间" + System.currentTimeMillis());
            redisUtil.set(mobile + "," + event, String.valueOf(code), 300);

//            log.error("短信服务调起时间"+System.currentTimeMillis());
            sendSmsResponse = AliMessageSend.sendSms(mobile, JSONObject.toJSONString(map), "SMS_139570048");
//            log.error("手机验证码"+sendSmsResponse);
//            log.error("短信服务响应时间"+System.currentTimeMillis());
//            log.error("*************结束*************");
        }
        return sendSmsResponse;
    }

    /**
     * 短信验证
     *
     * @param mobile  手机号码
     * @param event   事件
     * @param captcha 验证码
     * @return
     */
    @Override
    public int check(String mobile, String event, String captcha) {

        int num = 0;
        //检测redis是否过期
        if (!redisUtil.hasKey(mobile + "," + event)) {
            return num = 1;
        }

        String result = (String) redisUtil.get(mobile + "," + event);
        //取redis中缓存数据
        if (!StringUtils.equals(result, captcha) || result == null) {
            return num = 2;
        }
        //验证成功,删除redis缓存数据
        redisUtil.del(mobile + "," + event);

        return num;
    }

    /**
     * 自定义短信内容发送
     * @param msg 短信内容
     * @param mobile 用户手机号
     * @return
     */
    @Override
    public String tencentSendMess(String msg, String mobile) {
        try {
            SmsSingleSender ssender = new SmsSingleSender(tencentAppId, tencentAppkey);
            SmsSingleSenderResult result = ssender.send(0, "86", mobile,
                    msg, "", "");
            System.out.print(result);
            return result.errMsg;
        } catch (HTTPException e) {
            // HTTP响应码错误
            e.printStackTrace();
        } catch (JSONException e) {
            // json解析错误
            e.printStackTrace();
        } catch (IOException e) {
            // 网络IO错误
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 指定模板id发送短信
     * @param mobile
     * @return
     */
    @Override
    public String tencentSendMesModel(String mobile) {
        try {
            String[] params = {"hello" , "1" };//{参数}
            SmsSingleSender ssender = new SmsSingleSender(tencentAppId, tencentAppkey);
            SmsSingleSenderResult result = ssender.sendWithParam("86", mobile,
                    tencentTemplateId, params, tencentSmsSign, "", "");  // 签名参数未提供或者为空时，会使用默认签名发送短信
            System.out.print(result);
            return result.errMsg;//OK
        } catch (HTTPException e) {
            // HTTP响应码错误
            e.printStackTrace();
        } catch (JSONException e) {
            // json解析错误
            e.printStackTrace();
        } catch (IOException e) {
            // 网络IO错误
            e.printStackTrace();
        }
        return null;

    }

    /**
     * 群发自定义短信
     * @param msg
     * @param mobile
     * @return
     */
    @Override
    public String tencentSendMesModel(String msg, String[] mobile) {
        try {
            SmsSingleSender ssender = new SmsSingleSender(tencentAppId, tencentAppkey);
            SmsSingleSenderResult result = ssender.send(0, "86", String.valueOf(mobile),
                    msg, "", "");
            System.out.print(result);
            return result.errMsg;
        } catch (HTTPException e) {
            // HTTP响应码错误
            e.printStackTrace();
        } catch (JSONException e) {
            // json解析错误
            e.printStackTrace();
        } catch (IOException e) {
            // 网络IO错误
            e.printStackTrace();
        }
        return null;

    }

    /**
     * 指定模板ID群发
     * @param mobile
     * @return
     */
    @Override
    public String tencentSendMesModel(String[] mobile) {

        try {
            String[] params = {"5678"};
            SmsMultiSender msender = new SmsMultiSender(tencentAppId, tencentAppkey);
            SmsMultiSenderResult result =  msender.sendWithParam("86", mobile,
                    tencentTemplateId, params, tencentSmsSign, "", "");  // 签名参数未提供或者为空时，会使用默认签名发送短信
            System.out.println(result);
        } catch (HTTPException e) {
            // HTTP响应码错误
            e.printStackTrace();
        } catch (JSONException e) {
            // json解析错误
            e.printStackTrace();
        } catch (IOException e) {
            // 网络IO错误
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 发送语音消息
     * @param msg
     * @param mobile
     * @return
     */
    @Override
    public String sendMesVoice(String msg, String mobile) {
        try {
            SmsVoiceVerifyCodeSender vvcsender = new SmsVoiceVerifyCodeSender(tencentAppId,tencentAppkey);
            SmsVoiceVerifyCodeSenderResult result = vvcsender.send("86",mobile,
                    msg, 2, "");
            System.out.print(result);
            return result.errMsg;
        } catch (HTTPException e) {
            // HTTP响应码错误
            e.printStackTrace();
        } catch (JSONException e) {
            // json解析错误
            e.printStackTrace();
        } catch (IOException e) {
            // 网络IO错误
            e.printStackTrace();
        }
        return null;
    }

}
