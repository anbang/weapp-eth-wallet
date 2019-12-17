//index.js
//获取应用实例
const app = getApp()
var fs = wx.getFileSystemManager()
console.log('fs', fs);
fs.writeFileSync(`${wx.env.USER_DATA_PATH}/hello2.txt`, 'hello, Anbang', 'utf8')

var files = fs.readdirSync(wx.env.USER_DATA_PATH);
var fileInfo = fs.readFileSync(`${wx.env.USER_DATA_PATH}/hello.txt`, 'utf8');
console.log('files', files);
console.log('文件内容：', fileInfo);
//本地用户文件

(async () => {
  var Accounts = require('czr-account')  // note: the trailing slash is important!
  var accounts = new Accounts(true)

  // 目标数据
  var prKey = "5e844ee4d2e26920f8b0c4b7846929057cfce48bf40ba269b173648999630053".toUpperCase();
  let testfile = {
    account: 'czr_3M3dbuG3hWoeykQroyhJssdS15Bzocyh7wryG75qUWDxoyzBca',
    kdf_salt: 'AF8460A7D28A396C62D6C51620B87789',
    iv: 'A695DDC35ED9F3183A09FED1E6D92083',
    ciphertext: '96D6B77BC031116919956F1904F25601C29036A9232D638536964E8ADC034360'
  }
  // sign 用的数据
  const mock = {
    prv: '0000000000000000000000000000000000000000000000000000000000000000',
    pub: '3B6A27BCCEB6A42D62A3A8D02A6F0D73653215771DE243A63AC048A18B59DA29',
    message: '5E844EE4D2E26920F8B0C4B7846929057CFCE48BF40BA269B173648999630053',
    signature: 'AD1E0EEBF552D40608F0D7FF43C2C85B60C2F259D2917FB37B6BC5D468147612BAB9F46FEEE6C2DC5F52C83E564E35457317DC47AFB179574178230BDF68A80E',
  }

  const createAcc = await accounts.create(123456);
  // console.log('创建账号:', createAcc.account === testfile.account)
  console.log('创建账号:\n', createAcc)

  const valiAcc = await accounts.validateAccount(createAcc, '123456');
  console.log('验证 创建账号:', valiAcc ? ("通过 " + createAcc.account) : "未通过")

  const decryptAcc = await accounts.decrypt(testfile, '123456');
  console.log('验证 解析账号:', prKey === decryptAcc ? "通过" : "未通过")

  const sig = await accounts.sign(mock.message, mock.prv)
  console.log('验证 签名结果:', sig === mock.signature ? "通过" : "未通过")
})()

Page({
  data: {
    motto: `${files}---${fileInfo}`,
    userInfo: {},
    hasUserInfo: false,
    canIUse: wx.canIUse('button.open-type.getUserInfo')
  },
  //事件处理函数
  bindViewTap: function () {
    wx.navigateTo({
      url: '../logs/logs'
    })
  },
  onLoad: function () {
    if (app.globalData.userInfo) {
      this.setData({
        userInfo: app.globalData.userInfo,
        hasUserInfo: true
      })
    } else if (this.data.canIUse) {
      // 由于 getUserInfo 是网络请求，可能会在 Page.onLoad 之后才返回
      // 所以此处加入 callback 以防止这种情况
      app.userInfoReadyCallback = res => {
        this.setData({
          userInfo: res.userInfo,
          hasUserInfo: true
        })
      }
    } else {
      // 在没有 open-type=getUserInfo 版本的兼容处理
      wx.getUserInfo({
        success: res => {
          app.globalData.userInfo = res.userInfo
          this.setData({
            userInfo: res.userInfo,
            hasUserInfo: true
          })
        }
      })
    }
  },
  getUserInfo: function (e) {
    console.log(e)
    app.globalData.userInfo = e.detail.userInfo
    this.setData({
      userInfo: e.detail.userInfo,
      hasUserInfo: true
    })
  }
})
