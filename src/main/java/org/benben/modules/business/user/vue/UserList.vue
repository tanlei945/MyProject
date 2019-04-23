<template>
  <a-card :bordered="false">

    <!-- 查询区域 -->
    <div class="table-page-search-wrapper">
      <a-form layout="inline">
        <a-row :gutter="24">

          <a-col :md="6" :sm="8">
            <a-form-item label="组别ID">
              <a-input placeholder="请输入组别ID" v-model="queryParam.groupId"></a-input>
            </a-form-item>
          </a-col>
          <a-col :md="6" :sm="8">
            <a-form-item label="用户名">
              <a-input placeholder="请输入用户名" v-model="queryParam.username"></a-input>
            </a-form-item>
          </a-col>
          <template v-if="toggleSearchStatus">
            <a-col :md="6" :sm="8">
              <a-form-item label="真实姓名">
                <a-input placeholder="请输入真实姓名" v-model="queryParam.realname"></a-input>
              </a-form-item>
            </a-col>
            <a-col :md="6" :sm="8">
              <a-form-item label="昵称">
                <a-input placeholder="请输入昵称" v-model="queryParam.nickname"></a-input>
              </a-form-item>
            </a-col>
            <a-col :md="6" :sm="8">
              <a-form-item label="密码">
                <a-input placeholder="请输入密码" v-model="queryParam.password"></a-input>
              </a-form-item>
            </a-col>
          </template>
          <a-col :md="6" :sm="8" >
            <span style="float: left;overflow: hidden;" class="table-page-search-submitButtons">
              <a-button type="primary" @click="searchQuery" icon="search">查询</a-button>
              <a-button type="primary" @click="searchReset" icon="reload" style="margin-left: 8px">重置</a-button>
              <a @click="handleToggleSearch" style="margin-left: 8px">
                {{ toggleSearchStatus ? '收起' : '展开' }}
                <a-icon :type="toggleSearchStatus ? 'up' : 'down'"/>
              </a>
            </span>
          </a-col>

        </a-row>
      </a-form>
    </div>

    <!-- 操作按钮区域 -->
    <div class="table-operator">
      <a-button @click="handleAdd" type="primary" icon="plus">新增</a-button>
      <a-button type="primary" icon="download" @click="handleExportXls">导出</a-button>
      <a-upload name="file" :showUploadList="false" :multiple="false" :action="importExcelUrl" @change="handleImportExcel">
        <a-button type="primary" icon="import">导入</a-button>
      </a-upload>
      <a-dropdown v-if="selectedRowKeys.length > 0">
        <a-menu slot="overlay">
          <a-menu-item key="1" @click="batchDel"><a-icon type="delete"/>删除</a-menu-item>
        </a-menu>
        <a-button style="margin-left: 8px"> 批量操作 <a-icon type="down" /></a-button>
      </a-dropdown>
    </div>

    <!-- table区域-begin -->
    <div>
      <div class="ant-alert ant-alert-info" style="margin-bottom: 16px;">
        <i class="anticon anticon-info-circle ant-alert-icon"></i> 已选择 <a style="font-weight: 600">{{ selectedRowKeys.length }}</a>项
        <a style="margin-left: 24px" @click="onClearSelected">清空</a>
      </div>

      <a-table
              ref="table"
              size="middle"
              bordered
              rowKey="id"
              :columns="columns"
              :dataSource="dataSource"
              :pagination="ipagination"
              :loading="loading"
              :rowSelection="{selectedRowKeys: selectedRowKeys, onChange: onSelectChange}"
              @change="handleTableChange">

        <span slot="action" slot-scope="text, record">
          <a @click="handleEdit(record)">编辑</a>

          <a-divider type="vertical" />
          <a-dropdown>
            <a class="ant-dropdown-link">更多 <a-icon type="down" /></a>
            <a-menu slot="overlay">
              <a-menu-item>
                <a-popconfirm title="确定删除吗?" @confirm="() => handleDelete(record.id)">
                  <a>删除</a>
                </a-popconfirm>
              </a-menu-item>
            </a-menu>
          </a-dropdown>
        </span>

      </a-table>
    </div>
    <!-- table区域-end -->

    <!-- 表单区域 -->
    <user-modal ref="modalForm" @ok="modalFormOk"></user-modal>
  </a-card>
</template>

<script>
  import UserModal from './modules/UserModal'
  import { JeecgListMixin } from '@/mixins/JeecgListMixin'

  export default {
    name: "UserList",
    mixins:[JeecgListMixin],
    components: {
      UserModal
    },
    data () {
      return {
        description: '普通用户管理页面',
        // 表头
        columns: [
          {
            title: '#',
            dataIndex: '',
            key:'rowIndex',
            width:60,
            align:"center",
            customRender:function (t,r,index) {
              return parseInt(index)+1;
            }
          },
          {
            title: '组别ID',
            align:"center",
            dataIndex: 'groupId'
          },
          {
            title: '用户名',
            align:"center",
            dataIndex: 'username'
          },
          {
            title: '真实姓名',
            align:"center",
            dataIndex: 'realname'
          },
          {
            title: '昵称',
            align:"center",
            dataIndex: 'nickname'
          },
          {
            title: '密码',
            align:"center",
            dataIndex: 'password'
          },
          {
            title: '密码盐',
            align:"center",
            dataIndex: 'salt'
          },
          {
            title: '用户类型  0/普通用户,1/骑手',
            align:"center",
            dataIndex: 'userType'
          },
          {
            title: '电子邮箱',
            align:"center",
            dataIndex: 'email'
          },
          {
            title: '手机号',
            align:"center",
            dataIndex: 'mobile'
          },
          {
            title: '头像',
            align:"center",
            dataIndex: 'avatar'
          },
          {
            title: '等级',
            align:"center",
            dataIndex: 'userLevel'
          },
          {
            title: '性别  0/男,1/女',
            align:"center",
            dataIndex: 'sex'
          },
          {
            title: '生日',
            align:"center",
            dataIndex: 'birthday'
          },
          {
            title: '格言',
            align:"center",
            dataIndex: 'bio'
          },
          {
            title: '余额',
            align:"center",
            dataIndex: 'userMoney'
          },
          {
            title: '积分',
            align:"center",
            dataIndex: 'score'
          },
          {
            title: '连续登录天数',
            align:"center",
            dataIndex: 'successIons'
          },
          {
            title: '最大连续登录天数',
            align:"center",
            dataIndex: 'maxsuccessIons'
          },
          {
            title: '上次登录时间',
            align:"center",
            dataIndex: 'prevTime'
          },
          {
            title: '登录时间',
            align:"center",
            dataIndex: 'loginTime'
          },
          {
            title: '登录IP',
            align:"center",
            dataIndex: 'loginip'
          },
          {
            title: '失败次数',
            align:"center",
            dataIndex: 'loginfailure'
          },
          {
            title: '加入IP',
            align:"center",
            dataIndex: 'joinip'
          },
          {
            title: '加入时间',
            align:"center",
            dataIndex: 'joinTime'
          },
          {
            title: '状态(1：正常  2：冻结 ）',
            align:"center",
            dataIndex: 'status'
          },
          {
            title: '删除状态  0/正常,1/已删除',
            align:"center",
            dataIndex: 'delFlag'
          },
          {
            title: '邀请人',
            align:"center",
            dataIndex: 'inviterId'
          },
          {
            title: '操作',
            dataIndex: 'action',
            align:"center",
            scopedSlots: { customRender: 'action' },
          }
        ],
        url: {
          list: "/user/list",
          delete: "/user/delete",
          deleteBatch: "/user/deleteBatch",
          exportXlsUrl: "user/exportXls",
          importExcelUrl: "user/importExcel",
        },
      }
    },
    computed: {
      importExcelUrl: function(){
        return `${window._CONFIG['domianURL']}/${this.url.importExcelUrl}`;
      }
    },
    methods: {

    }
  }
</script>
<style lang="less" scoped>
  /** Button按钮间距 */
  .ant-btn {
    margin-left: 3px
  }
  .ant-card-body .table-operator{
    margin-bottom: 18px;
  }
  .ant-table-tbody .ant-table-row td{
    padding-top:15px;
    padding-bottom:15px;
  }
  .anty-row-operator button{margin: 0 5px}
  .ant-btn-danger{background-color: #ffffff}

  .ant-modal-cust-warp{height: 100%}
  .ant-modal-cust-warp .ant-modal-body{height:calc(100% - 110px) !important;overflow-y: auto}
  .ant-modal-cust-warp .ant-modal-content{height:90% !important;overflow-y: hidden}
</style>