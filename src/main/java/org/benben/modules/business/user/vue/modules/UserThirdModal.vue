<template>
  <a-modal
          :title="title"
          :width="800"
          :visible="visible"
          :confirmLoading="confirmLoading"
          @ok="handleOk"
          @cancel="handleCancel"
          cancelText="关闭">

    <a-spin :spinning="confirmLoading">
      <a-form :form="form">

        <a-form-item
                :labelCol="labelCol"
                :wrapperCol="wrapperCol"
                label="用户ID">
          <a-input placeholder="请输入用户ID" v-decorator="['userId', {}]" />
        </a-form-item>
        <a-form-item
                :labelCol="labelCol"
                :wrapperCol="wrapperCol"
                label="QQ_OpenId">
          <a-input placeholder="请输入QQ_OpenId" v-decorator="['qqOpenid', {}]" />
        </a-form-item>
        <a-form-item
                :labelCol="labelCol"
                :wrapperCol="wrapperCol"
                label="微信_OpenId">
          <a-input placeholder="请输入微信_OpenId" v-decorator="['wxOpenid', {}]" />
        </a-form-item>
        <a-form-item
                :labelCol="labelCol"
                :wrapperCol="wrapperCol"
                label="微博_OpenId">
          <a-input placeholder="请输入微博_OpenId" v-decorator="['wbOpenid', {}]" />
        </a-form-item>
        <a-form-item
                :labelCol="labelCol"
                :wrapperCol="wrapperCol"
                label="状态  0/启用,1/未启用,2/已删除">
          <a-input placeholder="请输入状态  0/启用,1/未启用,2/已删除" v-decorator="['status', {}]" />
        </a-form-item>

      </a-form>
    </a-spin>
  </a-modal>
</template>

<script>
  import { httpAction } from '@/api/manage'
  import pick from 'lodash.pick'
  import moment from "moment"

  export default {
    name: "UserThirdModal",
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
        },
        url: {
          add: "/user/userThird/add",
          edit: "/user/userThird/edit",
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
          this.form.setFieldsValue(pick(this.model,'userId','qqOpenid','wxOpenid','wbOpenid','status'))
          //时间格式化
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

<style scoped>

</style>