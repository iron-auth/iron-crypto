const Iron = require('@hapi/iron');

const password = 'passwordpasswordpasswordpasswordpasswordpasswordpasswordpassword';
const message = "Hello World!"

const aes256cbcOptions = {
  algorithm: 'aes-256-cbc',
  iterations: 2,
  minPasswordlength: 32,
  saltBits: 256,
  salt: 'b27a06366ace6bb1560ea039a5595c352a429b87f3982542da9e830a32f5468e',
  iv: Buffer.from([0xac, 0xc6, 0x9d, 0x62, 0x8a, 0x2b, 0x0e, 0x54, 0x55, 0x30, 0xd5, 0x82, 0xed, 0xdc, 0x49, 0x27]),
}

const aes128ctrOptions = {
  algorithm: 'aes-128-ctr',
  iterations: 2,
  minPasswordlength: 32,
  saltBits: 256,
  salt: 'b27a06366ace6bb1560ea039a5595c352a429b87f3982542da9e830a32f5468e',
  iv: Buffer.from([0xac, 0xc6, 0x9d, 0x62, 0x8a, 0x2b, 0x0e, 0x54, 0x55, 0x30, 0xd5, 0x82, 0xed, 0xdc, 0x49, 0x27]),
}

// Iron.encrypt(password, aes256cbcOptions, message).then((encrypted) => {
//   console.log('encrypt - aes256cbc:', encrypted);
// });

// Iron.encrypt(password, aes128ctrOptions, message).then((encrypted) => {
//   console.log('encrypt - aes128ctr:', encrypted);
// });

const sha256Options = {
  algorithm: 'sha256',
  iterations: 2,
  minPasswordlength: 32,
  saltBits: 256,
  salt: 'b27a06366ace6bb1560ea039a5595c352a429b87f3982542da9e830a32f5468e',
  iv: Buffer.from([0xac, 0xc6, 0x9d, 0x62, 0x8a, 0x2b, 0x0e, 0x54, 0x55, 0x30, 0xd5, 0x82, 0xed, 0xdc, 0x49, 0x27]),
}

Iron.generateKey(password, sha256Options).then((key) => {
  console.log('generateKey - sha256:', key);
});

Iron.hmacWithPassword(password, sha256Options, message).then((hmac) => {
  console.log('hmacWithPassword - sha256:', hmac);
});
