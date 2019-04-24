package org.benben.modules.business.user.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.qq.connect.QQConnectException;
import com.qq.connect.utils.QQConnectConfig;
import org.benben.modules.business.user.entity.User;
import org.benben.modules.business.user.entity.UserThird;
import org.benben.modules.business.user.mapper.UserThirdMapper;
import org.benben.modules.business.user.mapper.UserMapper;
import org.benben.modules.business.user.service.IUserService;
import org.springframework.stereotype.Service;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

import java.io.Serializable;
import java.util.Collection;

/**
 * @Description: 普通用户
 * @author： jeecg-boot
 * @date：   2019-04-20
 * @version： V1.0
 */
@Service
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements IUserService {

	@Autowired
	private UserMapper userMapper;
	@Autowired
	private UserThirdMapper userThirdMapper;

//	@Override
//	@Transactional
//	public void saveMain(User user, List<UserThird> userThirdList) {
//		userMapper.insert(user);
//		for(UserThird entity:userThirdList) {
//			//外键设置
//			entity.setUserId(user.getId());
//			userThirdMapper.insert(entity);
//		}
//	}
//
//	@Override
//	@Transactional
//	public void updateMain(User user,List<UserThird> userThirdList) {
//		userMapper.updateById(user);
//
//		//1.先删除子表数据
//		userThirdMapper.deleteByMainId(user.getId());
//
//		//2.子表数据重新插入
//		for(UserThird entity:userThirdList) {
//			//外键设置
//			entity.setUserId(user.getId());
//			userThirdMapper.insert(entity);
//		}
//	}

	@Override
	@Transactional
	public void delMain(String id) {
		userMapper.deleteById(id);
		userThirdMapper.deleteByMainId(id);
	}

	@Override
	@Transactional
	public void delBatchMain(Collection<? extends Serializable> idList) {
		for(Serializable id:idList) {
			userMapper.deleteById(id);
			userThirdMapper.deleteByMainId(id.toString());
		}
	}

	@Override
	public User queryByUsername(String username) {
		QueryWrapper<User> userInfoQueryWrapper = new QueryWrapper<>();
		userInfoQueryWrapper.eq("username", username);
		User user = userMapper.selectOne(userInfoQueryWrapper);
		return user;
	}

	@Override
	public User queryByMobile(String moblie) {
		QueryWrapper<User> userInfoQueryWrapper = new QueryWrapper<>();
		userInfoQueryWrapper.eq("mobile", moblie);
		User userInfo = userMapper.selectOne(userInfoQueryWrapper);
		return userInfo;
	}

	/**
	 * 绑定三方信息
	 * @param openId 识别
	 * @param userId 用户ID
	 * @param type 类型  0/QQ,1/微信,2/微博
	 * @return
	 */
	@Override
	@Transactional
	public int bindingThird(String openId, String userId, String type) {

		UserThird userThird = new UserThird();
		userThird.setUserId(userId);
		userThird.setOpenId(openId);
		userThird.setOpenType(type);

		return userThirdMapper.insert(userThird);
	}


	/**
	 * 忘记密码
	 * @param mobile
	 * @param password
	 * @return
	 */
	@Override
	@Transactional
	public int forgetPassword(String mobile, String password) {

		QueryWrapper<User> queryWrapper = new QueryWrapper<>();
		queryWrapper.eq("mobile",mobile);

		User user = userMapper.selectOne(queryWrapper);
		if(user == null){
			return 0;
		}

		user.setPassword(password);

		return userMapper.insert(user);
	}


	public String getAuthorizeURL(String response_type, String state, String scope) throws QQConnectException {
		return QQConnectConfig.getValue("authorizeURL").trim() + "?client_id=" + QQConnectConfig.getValue("app_ID").trim() + "&redirect_uri=" + QQConnectConfig.getValue("redirect_URI").trim() + "&response_type=" + response_type + "&state=" + state + "&scope=" + scope;
	}
}
