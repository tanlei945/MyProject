package org.benben.modules.business.user.vo;

import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

@Data
public class UserVo {

	private String id;
	@ApiModelProperty(value = "用户名",name = "username")
	private String username;
	@ApiModelProperty(value = "用户类型  0/普通用户,1/骑手",name = "userType")
	private String userType;
	@ApiModelProperty(value = "手机号",name = "mobile")
	private String mobile;
	@ApiModelProperty(value = "头像",name = "avatar")
	private String avatar;
	@ApiModelProperty(value = "性别",name = "sex")
	private Integer sex;
	@ApiModelProperty(value = "余额",name = "money")
	private Double money;
	@ApiModelProperty(value = "优惠券数量",name = "couponsNumber")
	private Integer couponsNumber;

}
