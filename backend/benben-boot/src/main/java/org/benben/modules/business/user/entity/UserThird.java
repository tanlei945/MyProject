package org.benben.modules.business.user.entity;

import java.io.Serializable;
import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;
import com.fasterxml.jackson.annotation.JsonFormat;
import org.springframework.format.annotation.DateTimeFormat;
import org.jeecgframework.poi.excel.annotation.Excel;
import java.util.Date;

/**
 * @Description: 用户三方关联
 * @author： jeecg-boot
 * @date：   2019-04-23
 * @version： V1.0
 */
@Data
@TableName("user_third")
public class UserThird implements Serializable {
	private static final long serialVersionUID = 1L;

	/**id*/
	@TableId(type = IdType.UUID)
	private java.lang.String id;
	/**用户ID*/
	private java.lang.String userId;
	/**状态  0/QQ,1/微信,2/微博*/
	@Excel(name = "状态  0/QQ,1/微信,2/微博", width = 15)
	private java.lang.String openType;
	/**OpenId*/
	@Excel(name = "OpenId", width = 15)
	private java.lang.String openId;
	/**状态  0/启用,1/未启用,2/已删除*/
	@Excel(name = "状态  0/启用,1/未启用,2/已删除", width = 15)
	private java.lang.String status;
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
}
