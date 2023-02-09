const Iron = require('@hapi/iron');

const password = 'passwordpasswordpasswordpasswordpasswordpasswordpasswordpassword';

Iron.generateKey(password, {
  algorithm: 'aes-256-cbc',
  iterations: 2,
  minPasswordlength: 32,
  saltBits: 256,
  salt: 'b27a06366ace6bb1560ea039a5595c352a429b87f3982542da9e830a32f5468e',
  iv: Buffer.from([0xac, 0xc6, 0x9d, 0x62, 0x8a, 0x2b, 0x0e, 0x54, 0x55, 0x30, 0xd5, 0x82, 0xed, 0xdc, 0x49, 0x27]),
}).then((key) => {
  console.log(key);
});