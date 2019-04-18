package org.benben.common.api.vo;


/**
 * @author: WangHao
 * @date: 2019/4/8 0008
 * @description:
 */
public class RestResponseBean {

    // http 状态码
    private int code;

    // 返回信息
    private String msg;

    // 返回时间戳
    private String time = String.valueOf(System.currentTimeMillis());

    // 返回的数据
    private Object data;


    public RestResponseBean() {
    }

    public RestResponseBean(int code, String msg, Object data) {
        this.code = code;
        this.msg = msg;
        this.data = data;
    }


    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public String getMsg() {
        return msg;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }

    public String getTime() {
        return time;
    }

    public void setTime(String time) {
        this.time = time;
    }

    public Object getData() {
        return data;
    }

    public void setData(Object data) {
        this.data = data;
    }
}
