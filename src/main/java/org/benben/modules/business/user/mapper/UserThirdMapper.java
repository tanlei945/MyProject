package org.benben.modules.business.user.mapper;

import java.util.List;
import org.benben.modules.business.user.entity.UserThird;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;

/**
 * @Description: 用户三方关联
 * @author： jeecg-boot
 * @date：   2019-04-20
 * @version： V1.0
 */
public interface UserThirdMapper extends BaseMapper<UserThird> {

	public boolean deleteByMainId(String mainId);
    
	public List<UserThird> selectByMainId(String mainId);

}
