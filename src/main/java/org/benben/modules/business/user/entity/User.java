package org.benben.modules.business.user.entity;

import java.io.Serializable;
import java.util.Date;
import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;
import com.fasterxml.jackson.annotation.JsonFormat;
import org.springframework.format.annotation.DateTimeFormat;
import org.jeecgframework.poi.excel.annotation.Excel;

/**
 * @Description: 普通用户
 * @author： jeecg-boot
 * @date：   2019-04-23
 * @version： V1.0
 */
@Data
@TableName("user")
public class User implements Serializable {
	private static final long serialVersionUID = 1L;

	/**ID*/
	@TableId(type = IdType.UUID)
	private java.lang.String id;
	/**组别ID*/
	@Excel(name = "组别ID", width = 15)
	private java.lang.String groupId;
	/**用户名*/
	@Excel(name = "用户名", width = 15)
	private java.lang.String username;
	/**真实姓名*/
	@Excel(name = "真实姓名", width = 15)
	private java.lang.String realname;
	/**昵称*/
	@Excel(name = "昵称", width = 15)
	private java.lang.String nickname;
	/**密码*/
	@Excel(name = "密码", width = 15)
	private java.lang.String password;
	/**密码盐*/
	@Excel(name = "密码盐", width = 15)
	private java.lang.String salt;
	/**用户类型  0/普通用户,1/骑手*/
	@Excel(name = "用户类型  0/普通用户,1/骑手", width = 15)
	private java.lang.String userType;
	/**电子邮箱*/
	@Excel(name = "电子邮箱", width = 15)
	private java.lang.String email;
	/**手机号*/
	@Excel(name = "手机号", width = 15)
	private java.lang.String mobile;
	/**头像*/
	@Excel(name = "头像", width = 15)
	private java.lang.String avatar;
	/**等级*/
	@Excel(name = "等级", width = 15)
	private java.lang.Integer userLevel;
	/**性别  0/男,1/女*/
	@Excel(name = "性别  0/男,1/女", width = 15)
	private java.lang.Integer sex;
	/**生日*/
	@Excel(name = "生日", width = 20, format = "yyyy-MM-dd HH:mm:ss")
	@JsonFormat(timezone = "GMT+8",pattern = "yyyy-MM-dd HH:mm:ss")
	@DateTimeFormat(pattern="yyyy-MM-dd HH:mm:ss")
	private java.util.Date birthday;
	/**格言*/
	@Excel(name = "格言", width = 15)
	private java.lang.String bio;
	/**余额*/
	@Excel(name = "余额", width = 15)
	private java.math.BigDecimal userMoney;
	/**积分*/
	@Excel(name = "积分", width = 15)
	private java.lang.Integer score;
	/**连续登录天数*/
	@Excel(name = "连续登录天数", width = 15)
	private java.lang.Integer successIons;
	/**最大连续登录天数*/
	@Excel(name = "最大连续登录天数", width = 15)
	private java.lang.Integer maxsuccessIons;
	/**上次登录时间*/
	@Excel(name = "上次登录时间", width = 15)
	private java.lang.Integer prevTime;
	/**登录时间*/
	@Excel(name = "登录时间", width = 20, format = "yyyy-MM-dd HH:mm:ss")
	@JsonFormat(timezone = "GMT+8",pattern = "yyyy-MM-dd HH:mm:ss")
	@DateTimeFormat(pattern="yyyy-MM-dd HH:mm:ss")
	private java.util.Date loginTime;
	/**登录IP*/
	@Excel(name = "登录IP", width = 15)
	private java.lang.String loginip;
	/**失败次数*/
	@Excel(name = "失败次数", width = 15)
	private java.lang.Integer loginfailure;
	/**加入IP*/
	@Excel(name = "加入IP", width = 15)
	private java.lang.String joinip;
	/**加入时间*/
	@Excel(name = "加入时间", width = 20, format = "yyyy-MM-dd HH:mm:ss")
	@JsonFormat(timezone = "GMT+8",pattern = "yyyy-MM-dd HH:mm:ss")
	@DateTimeFormat(pattern="yyyy-MM-dd HH:mm:ss")
	private java.util.Date joinTime;
	/**创建时间*/
	@Excel(name = "创建时间", width = 20, format = "yyyy-MM-dd HH:mm:ss")
	@JsonFormat(timezone = "GMT+8",pattern = "yyyy-MM-dd HH:mm:ss")
	@DateTimeFormat(pattern="yyyy-MM-dd HH:mm:ss")
	private java.util.Date createTime;
	/**创建人*/
	@Excel(name = "创建人", width = 15)
	private java.lang.String createBy;
	/**更新时间*/
	@Excel(name = "更新时间", width = 20, format = "yyyy-MM-dd HH:mm:ss")
	@JsonFormat(timezone = "GMT+8",pattern = "yyyy-MM-dd HH:mm:ss")
	@DateTimeFormat(pattern="yyyy-MM-dd HH:mm:ss")
	private java.util.Date updateTime;
	/**编辑人*/
	@Excel(name = "编辑人", width = 15)
	private java.lang.String updateBy;
	/**状态(1：正常  2：冻结 ）*/
	@Excel(name = "状态(1：正常  2：冻结 ）", width = 15)
	private java.lang.Integer status;
	/**删除状态  0/正常,1/已删除*/
	@Excel(name = "删除状态  0/正常,1/已删除", width = 15)
	private java.lang.String delFlag;
	/**邀请人*/
	@Excel(name = "邀请人", width = 15)
	private java.lang.String inviterId;
}
