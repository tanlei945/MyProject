package org.benben.modules.business.user.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.benben.modules.business.user.entity.UserThird;
import org.benben.modules.business.user.mapper.UserThirdMapper;
import org.benben.modules.business.user.service.IUserThirdService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * @Description: 用户三方关联
 * @author： jeecg-boot
 * @date：   2019-04-20
 * @version： V1.0
 */
@Service
public class UserThirdServiceImpl extends ServiceImpl<UserThirdMapper, UserThird> implements IUserThirdService {

	@Autowired
	private UserThirdMapper userThirdMapper;

	@Override
	public List<UserThird> selectByMainId(String mainId) {
		return userThirdMapper.selectByMainId(mainId);
	}

	/**
	 * 根据openid查询绑定信息
	 * @param openid
	 * @return
	 */
	@Override
	public UserThird queryByOpenid(String openid) {

		QueryWrapper<UserThird> queryWrapper = new QueryWrapper<>();
		queryWrapper.eq("open_id",openid);

		return userThirdMapper.selectOne(queryWrapper);
	}
}
