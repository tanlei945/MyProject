package org.benben.modules.business.user.service;

import com.qq.connect.QQConnectException;
import org.benben.common.api.vo.RestResponseBean;
import org.benben.modules.business.user.entity.UserThird;
import org.benben.modules.business.user.entity.User;
import com.baomidou.mybatisplus.extension.service.IService;

import javax.servlet.ServletRequest;
import java.io.Serializable;
import java.util.Collection;
import java.util.List;

/**
 * @Description: 普通用户
 * @author： jeecg-boot
 * @date：   2019-04-20
 * @version： V1.0
 */
public interface IUserService extends IService<User> {

//	/**
//	 * 添加一对多
//	 *
//	 */
//	public void saveMain(User user,List<UserThird> userThirdList) ;
//
//	/**
//	 * 修改一对多
//	 *
//	 */
//	public void updateMain(User user,List<UserThird> userThirdList);

	/**
	 * 删除一对多
	 */
	public void delMain (String id);

	/**
	 * 批量删除一对多
	 */
	public void delBatchMain (Collection<? extends Serializable> idList);

	public User queryByUsername(String username);

	public User queryByMobile(String moblie);

	public int bindingThird(String openId , String userId, String type);

	public String getQQURL(ServletRequest request) throws QQConnectException;

	public int forgetPassword(String mobile, String password);

}
