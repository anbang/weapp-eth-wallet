let Accounts = require("./account.js");
let accounts = new Accounts();

// accounts.create(123456).then(res => {
//     console.log("创建账号收到结果\n", res);//res.account
// }).catch(err => {
//     console.log("err===>", err);
// });


let keyStore = {
    "account": "czr_3PNjPuXG5bZ2DXdxh1rB82qL65d4nosYFQGJXRKecxJHEBfNB4",
    "kdf_salt": "3188085361BF6CFBA17A76C8F800A77D9B105512217FA18C0D62903637759F9D",
    "iv": "E91AFFAAFA59D1EC9D0190E285A23A76",
    "ciphertext": "389FE5C5843A42AFEE7140E045986E6A284F097FFEB8F760335905138B150FE6"
};

//TODO 解密账号私钥 9E91AC7B6E32AEB68A1AA5ECA5CBE24481B412CC129E15A0102D3A6003D2BA0A
accounts.decrypt(keyStore, 2222).then(res => {
    console.log("1.解密账号收到结果 ", res);
    return res
}).catch(err => {
    console.log("decrypt err", err);
}).then(function (privateKey) {
    //TODO 签名
    let blockHash = '5E844EE4D2E26920F8B0C4B7846929057CFCE48BF40BA269B173648999630053';
    accounts.sign(blockHash, privateKey).then(signature => {
        //BBFE4DE008DE19C3178EABBAAF032319DDC493AE5E9174065A0E729945BA47CA9CAC6B6F5A509D8123FB1F4A62AD65D4B68E51A863E4BA7033696A89E1FD9C07
        console.log("2.signature ", signature)
    }).catch(err => {
        console.log("sign err", err);
    })
});