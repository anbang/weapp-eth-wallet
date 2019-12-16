const bs58check = require("bs58check");
function encodeAccount(pub) {
    console.log('encodeAccount收到', pub)
    let version = Buffer.from([0x01]);
    let v_pub = Buffer.concat([version, pub]);
    console.log("encodeAccount返回" + bs58check.encode(v_pub));
    return "czr_";
}

var aaa = Buffer.from([39, 94, 17, 211, 112, 192, 123, 56, 62, 77, 75, 105, 117, 153, 140, 57, 234, 118, 95, 49, 167, 159, 18, 31, 216, 209, 173, 184, 248, 84, 101, 215])
console.log(encodeAccount(aaa))