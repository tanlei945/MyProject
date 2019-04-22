package org.benben.modules.business.user.service;

import org.benben.modules.business.user.entity.UserThird;
import com.baomidou.mybatisplus.extension.service.IService;
import java.util.List;

/**
 * @Description: 用户三方关联
 * @author： jeecg-boot
 * @date：   2019-04-20
 * @version： V1.0
 */
public interface IUserThirdService extends IService<UserThird> {

	public List<UserThird> selectByMainId(String mainId);

	public UserThird queryByOpenid(String openid);

}
