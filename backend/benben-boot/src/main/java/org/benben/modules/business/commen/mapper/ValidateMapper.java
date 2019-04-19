package org.benben.modules.business.commen.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Select;
import org.benben.modules.business.user.entity.User;

/**
 * @Description: 会员表
 * @author： jeecg-boot
 * @date：   2019-04-08
 * @version： V1.0
 */

public interface ValidateMapper extends BaseMapper<User>{

    @Select("select * from user_info where id = #{id}")
    User userInfoValidate(String id);
    @Select("select id from user_info where email = #{email}")
    String isExistEmail(String email);
    @Select("select id from user_info where username = #{username}")
    String isExistuName(String username);
}
