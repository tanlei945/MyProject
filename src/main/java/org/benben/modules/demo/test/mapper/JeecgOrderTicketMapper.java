package org.benben.modules.demo.test.mapper;

import java.util.List;

import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Select;
import org.benben.modules.demo.test.entity.JeecgOrderTicket;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;

/**
 * @Description: 订单机票
 * @author： benben-boot
 * @date：   2019-02-15
 * @version： V1.0
 */
public interface JeecgOrderTicketMapper extends BaseMapper<JeecgOrderTicket> {

	/**
	 *  通过主表外键批量删除客户
	 * @param mainId
	 * @return
	 */
    @Delete("DELETE FROM JEECG_ORDER_TICKET WHERE ORDER_ID = #{mainId}")
	public boolean deleteTicketsByMainId(String mainId);
    
    
    @Select("SELECT * FROM JEECG_ORDER_TICKET WHERE ORDER_ID = #{mainId}")
	public List<JeecgOrderTicket> selectTicketsByMainId(String mainId);
}
