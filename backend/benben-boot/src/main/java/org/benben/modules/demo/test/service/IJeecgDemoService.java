package org.benben.modules.demo.test.service;

import org.benben.modules.demo.test.entity.JeecgDemo;

import com.baomidou.mybatisplus.extension.service.IService;

/**
 * @Description: benben 测试demo
 * @author： benben-boot
 * @date：   2018-12-29
 * @version： V1.0
 */
public interface IJeecgDemoService extends IService<JeecgDemo> {
	public void testTran();
	
	public JeecgDemo getByIdCacheable(String id);
}
