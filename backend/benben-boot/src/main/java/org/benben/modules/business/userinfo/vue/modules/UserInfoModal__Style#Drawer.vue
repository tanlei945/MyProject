<template>
  <a-drawer
      :title="title"
      :width="800"
      placement="right"
      :closable="false"
      @close="close"
      :visible="visible"
  >

    <a-spin :spinning="confirmLoading">
      <a-form :form="form">
      
        <a-form-item
          :labelCol="labelCol"
          :wrapperCol="wrapperCol"
          label="组别ID">
          <a-input placeholder="请输入组别ID" v-decorator="['groupId', validatorRules.groupId ]" />
        </a-form-item>
        <a-form-item
          :labelCol="labelCol"
          :wrapperCol="wrapperCol"
          label="用户名">
          <a-input placeholder="请输入用户名" v-decorator="['username', validatorRules.username ]" />
        </a-form-item>
        <a-form-item
          :labelCol="labelCol"
          :wrapperCol="wrapperCol"
          label="真实姓名">
          <a-input placeholder="请输入真实姓名" v-decorator="['realname', validatorRules.realname ]" />
        </a-form-item>
        <a-form-item
          :labelCol="labelCol"
          :wrapperCol="wrapperCol"
          label="昵称">
          <a-input placeholder="请输入昵称" v-decorator="['nickname', validatorRules.nickname ]" />
        </a-form-item>
        <a-form-item
          :labelCol="labelCol"
          :wrapperCol="wrapperCol"
          label="密码">
          <a-input placeholder="请输入密码" v-decorator="['password', validatorRules.password ]" />
        </a-form-item>
        <a-form-item
          :labelCol="labelCol"
          :wrapperCol="wrapperCol"
          label="密码盐">
          <a-input placeholder="请输入密码盐" v-decorator="['salt', validatorRules.salt ]" />
        </a-form-item>
        <a-form-item
          :labelCol="labelCol"
          :wrapperCol="wrapperCol"
          label="电子邮箱">
          <a-input placeholder="请输入电子邮箱" v-decorator="['email', validatorRules.email ]" />
        </a-form-item>
        <a-form-item
          :labelCol="labelCol"
          :wrapperCol="wrapperCol"
          label="手机号">
          <a-input placeholder="请输入手机号" v-decorator="['mobile', validatorRules.mobile ]" />
        </a-form-item>
        <a-form-item
          :labelCol="labelCol"
          :wrapperCol="wrapperCol"
          label="头像">
          <a-input placeholder="请输入头像" v-decorator="['avatar', validatorRules.avatar ]" />
        </a-form-item>
        <a-form-item
          :labelCol="labelCol"
          :wrapperCol="wrapperCol"
          label="等级">
          <a-input placeholder="请输入等级" v-decorator="['level', validatorRules.level ]" />
        </a-form-item>
        <a-form-item
          :labelCol="labelCol"
          :wrapperCol="wrapperCol"
          label="性别（1：男 2：女）">
          <a-input placeholder="请输入性别（1：男 2：女）" v-decorator="['sex', validatorRules.sex ]" />
        </a-form-item>
        <a-form-item
          :labelCol="labelCol"
          :wrapperCol="wrapperCol"
          label="生日">
          <a-date-picker showTime format='YYYY-MM-DD HH:mm:ss' v-decorator="[ 'birthday', {}]" />
        </a-form-item>
        <a-form-item
          :labelCol="labelCol"
          :wrapperCol="wrapperCol"
          label="格言">
          <a-input placeholder="请输入格言" v-decorator="['bio', validatorRules.bio ]" />
        </a-form-item>
        <a-form-item
          :labelCol="labelCol"
          :wrapperCol="wrapperCol"
          label="余额">
          <a-input-number v-decorator="[ 'money', validatorRules.money ]" />
        </a-form-item>
        <a-form-item
          :labelCol="labelCol"
          :wrapperCol="wrapperCol"
          label="积分">
          <a-input-number v-decorator="[ 'score', validatorRules.score ]" />
        </a-form-item>
        <a-form-item
          :labelCol="labelCol"
          :wrapperCol="wrapperCol"
          label="连续登录天数">
          <a-input-number v-decorator="[ 'successIons', validatorRules.successIons ]" />
        </a-form-item>
        <a-form-item
          :labelCol="labelCol"
          :wrapperCol="wrapperCol"
          label="最大连续登录天数">
          <a-input-number v-decorator="[ 'maxsuccessIons', validatorRules.maxsuccessIons ]" />
        </a-form-item>
        <a-form-item
          :labelCol="labelCol"
          :wrapperCol="wrapperCol"
          label="上次登录时间">
          <a-input-number v-decorator="[ 'prevTime', validatorRules.prevTime ]" />
        </a-form-item>
        <a-form-item
          :labelCol="labelCol"
          :wrapperCol="wrapperCol"
          label="登录时间">
          <a-input-number v-decorator="[ 'loginTime', validatorRules.loginTime ]" />
        </a-form-item>
        <a-form-item
          :labelCol="labelCol"
          :wrapperCol="wrapperCol"
          label="登录IP">
          <a-input placeholder="请输入登录IP" v-decorator="['loginip', validatorRules.loginip ]" />
        </a-form-item>
        <a-form-item
          :labelCol="labelCol"
          :wrapperCol="wrapperCol"
          label="失败次数">
          <a-input placeholder="请输入失败次数" v-decorator="['loginfailure', validatorRules.loginfailure ]" />
        </a-form-item>
        <a-form-item
          :labelCol="labelCol"
          :wrapperCol="wrapperCol"
          label="加入IP">
          <a-input placeholder="请输入加入IP" v-decorator="['joinip', validatorRules.joinip ]" />
        </a-form-item>
        <a-form-item
          :labelCol="labelCol"
          :wrapperCol="wrapperCol"
          label="加入时间">
          <a-date-picker showTime format='YYYY-MM-DD HH:mm:ss' v-decorator="[ 'joinTime', {}]" />
        </a-form-item>
        <a-form-item
          :labelCol="labelCol"
          :wrapperCol="wrapperCol"
          label="Token">
          <a-input placeholder="请输入Token" v-decorator="['token', validatorRules.token ]" />
        </a-form-item>
        <a-form-item
          :labelCol="labelCol"
          :wrapperCol="wrapperCol"
          label="状态(1：正常  2：冻结 ）">
          <a-input placeholder="请输入状态(1：正常  2：冻结 ）" v-decorator="['status', validatorRules.status ]" />
        </a-form-item>
        <a-form-item
          :labelCol="labelCol"
          :wrapperCol="wrapperCol"
          label="删除状态（0，正常，1已删除）">
          <a-input placeholder="请输入删除状态（0，正常，1已删除）" v-decorator="['delFlag', validatorRules.delFlag ]" />
        </a-form-item>
        <a-form-item
          :labelCol="labelCol"
          :wrapperCol="wrapperCol"
          label="验证">
          <a-input placeholder="请输入验证" v-decorator="['verification', validatorRules.verification ]" />
        </a-form-item>
        <a-form-item
          :labelCol="labelCol"
          :wrapperCol="wrapperCol"
          label="userId">
          <a-input placeholder="请输入userId" v-decorator="['userId', validatorRules.userId ]" />
        </a-form-item>
        <a-form-item
          :labelCol="labelCol"
          :wrapperCol="wrapperCol"
          label="创建时间整数类型">
          <a-input-number v-decorator="[ 'createtime', {}]" />
        </a-form-item>
        <a-form-item
          :labelCol="labelCol"
          :wrapperCol="wrapperCol"
          label="expiretime">
          <a-input-number v-decorator="[ 'expiretime', {}]" />
        </a-form-item>
        <a-form-item
          :labelCol="labelCol"
          :wrapperCol="wrapperCol"
          label="expiresIn">
          <a-input-number v-decorator="[ 'expiresIn', {}]" />
        </a-form-item>
        <a-form-item
          :labelCol="labelCol"
          :wrapperCol="wrapperCol"
          label="qqId">
          <a-input placeholder="请输入qqId" v-decorator="['qqId', {}]" />
        </a-form-item>
        <a-form-item
          :labelCol="labelCol"
          :wrapperCol="wrapperCol"
          label="wxId">
          <a-input placeholder="请输入wxId" v-decorator="['wxId', {}]" />
        </a-form-item>
		
      </a-form>
    </a-spin>
    <a-button type="primary" @click="handleOk">确定</a-button>
    <a-button type="primary" @click="handleCancel">取消</a-button>
  </a-drawer>
</template>

<script>
  import { httpAction } from '@/api/manage'
  import pick from 'lodash.pick'
  import moment from "moment"

  export default {
    name: "UserInfoModal",
    data () {
      return {
        title:"操作",
        visible: false,
        model: {},
        labelCol: {
          xs: { span: 24 },
          sm: { span: 5 },
        },
        wrapperCol: {
          xs: { span: 24 },
          sm: { span: 16 },
        },

        confirmLoading: false,
        form: this.$form.createForm(this),
        validatorRules:{
        groupId:{rules: [{ required: true, message: '请输入组别ID!' }]},
        username:{rules: [{ required: true, message: '请输入用户名!' }]},
        realname:{rules: [{ required: true, message: '请输入真实姓名!' }]},
        nickname:{rules: [{ required: true, message: '请输入昵称!' }]},
        password:{rules: [{ required: true, message: '请输入密码!' }]},
        salt:{rules: [{ required: true, message: '请输入密码盐!' }]},
        email:{rules: [{ required: true, message: '请输入电子邮箱!' }]},
        mobile:{rules: [{ required: true, message: '请输入手机号!' }]},
        avatar:{rules: [{ required: true, message: '请输入头像!' }]},
        level:{rules: [{ required: true, message: '请输入等级!' }]},
        sex:{rules: [{ required: true, message: '请输入性别（1：男 2：女）!' }]},
        bio:{rules: [{ required: true, message: '请输入格言!' }]},
        money:{rules: [{ required: true, message: '请输入余额!' }]},
        score:{rules: [{ required: true, message: '请输入积分!' }]},
        successIons:{rules: [{ required: true, message: '请输入连续登录天数!' }]},
        maxsuccessIons:{rules: [{ required: true, message: '请输入最大连续登录天数!' }]},
        prevTime:{rules: [{ required: true, message: '请输入上次登录时间!' }]},
        loginTime:{rules: [{ required: true, message: '请输入登录时间!' }]},
        loginip:{rules: [{ required: true, message: '请输入登录IP!' }]},
        loginfailure:{rules: [{ required: true, message: '请输入失败次数!' }]},
        joinip:{rules: [{ required: true, message: '请输入加入IP!' }]},
        token:{rules: [{ required: true, message: '请输入Token!' }]},
        status:{rules: [{ required: true, message: '请输入状态(1：正常  2：冻结 ）!' }]},
        delFlag:{rules: [{ required: true, message: '请输入删除状态（0，正常，1已删除）!' }]},
        verification:{rules: [{ required: true, message: '请输入验证!' }]},
        userId:{rules: [{ required: true, message: '请输入userId!' }]},
        },
        url: {
          add: "/userinfo/userInfo/add",
          edit: "/userinfo/userInfo/edit",
        },
      }
    },
    created () {
    },
    methods: {
      add () {
        this.edit({});
      },
      edit (record) {
        this.form.resetFields();
        this.model = Object.assign({}, record);
        this.visible = true;
        this.$nextTick(() => {
          this.form.setFieldsValue(pick(this.model,'groupId','username','realname','nickname','password','salt','email','mobile','avatar','level','sex','bio','money','score','successIons','maxsuccessIons','prevTime','loginTime','loginip','loginfailure','joinip','token','status','delFlag','verification','userId','createtime','expiretime','expiresIn','qqId','wxId'))
		  //时间格式化
          this.form.setFieldsValue({birthday:this.model.birthday?moment(this.model.birthday):null})
          this.form.setFieldsValue({joinTime:this.model.joinTime?moment(this.model.joinTime):null})
        });

      },
      close () {
        this.$emit('close');
        this.visible = false;
      },
      handleOk () {
        const that = this;
        // 触发表单验证
        this.form.validateFields((err, values) => {
          if (!err) {
            that.confirmLoading = true;
            let httpurl = '';
            let method = '';
            if(!this.model.id){
              httpurl+=this.url.add;
              method = 'post';
            }else{
              httpurl+=this.url.edit;
               method = 'put';
            }
            let formData = Object.assign(this.model, values);
            //时间格式化
            formData.birthday = formData.birthday?formData.birthday.format('YYYY-MM-DD HH:mm:ss'):null;
            formData.joinTime = formData.joinTime?formData.joinTime.format('YYYY-MM-DD HH:mm:ss'):null;
            
            console.log(formData)
            httpAction(httpurl,formData,method).then((res)=>{
              if(res.success){
                that.$message.success(res.message);
                that.$emit('ok');
              }else{
                that.$message.warning(res.message);
              }
            }).finally(() => {
              that.confirmLoading = false;
              that.close();
            })



          }
        })
      },
      handleCancel () {
        this.close()
      },


    }
  }
</script>

<style lang="less" scoped>
/** Button按钮间距 */
  .ant-btn {
    margin-left: 30px;
    margin-bottom: 30px;
    float: right;
  }
</style>