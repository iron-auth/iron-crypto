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

// Iron.generateKey(password, sha256Options).then((key) => {
//   console.log('generateKey - sha256:', key);
// });

// Iron.hmacWithPassword(password, sha256Options, message).then((hmac) => {
//   console.log('hmacWithPassword - sha256:', hmac);
// });

// Iron.seal(message, password, {
//   encryption: {
//     algorithm: 'aes-256-cbc',
//     iterations: 2,
//     minPasswordlength: 32,
//     saltBits: 256,
//   },
//   integrity: {
//     algorithm: 'sha256',
//     iterations: 2,
//     minPasswordlength: 32,
//     saltBits: 256,
//   },
//   ttl: 0,
//   timestampSkewSec: 0,
//   localtimeOffsetMsec: 0,
// }).then((s) => {
//   console.log('seal - aes256cbc:', s);
// });

//   Iron.unseal(sealed, password, {
//     encryption: {
//       algorithm: 'aes-256-cbc',
//       iterations: 2,
//       minPasswordlength: 32,
//       saltBits: 256,
//     },
//     integrity: {
//       algorithm: 'sha256',
//       iterations: 2,
//       minPasswordlength: 32,
//       saltBits: 256,
//     },
//     ttl: 0,
//     timestampSkewSec: 0,
//     localtimeOffsetMsec: 0,
//   }).then((sealed) => {
//     console.log('unseal - aes256cbc:', sealed);
//   });
  
// });

const sealedNode = "Fe26.2**a7635b415462affccd64d641bfb4c91fd557ecf9c3fea1fa84368850c173b39f*y7oSGBhrG6jyQBzNip-jrQ*ZsO9AppJhRSU4IZlpWlwLQ**a7efd8075c60daf921bfb73e408264f434d1d7dc44f847f4195772f30f6933ec*2ha-T1TJ26dqGpZCUdDZChRFE9D3heNLNSbw_SP6LW0";
const sealedGo = "Fe26.2**5c8074c7968402902cb644d2c552a416ae73d0b29af8215b7c98ecbe1c86af31*S8yjbJgU7Xgn-zjsen1TiQ*edmvCzfh3K5AAULEerrLvw**304664241a9d67c92c8589f49aeb0aa90af672c8e144ccdef4b04a4473fa1d08*xwzfk-UCjZXVNRqenqJXCuxxcXabRkaTp1WwI8nLrLc"

Iron.unseal(sealedGo, password, {
  encryption: {
    algorithm: 'aes-256-cbc',
    iterations: 2,
    minPasswordlength: 32,
    saltBits: 256,
  },
  integrity: {
    algorithm: 'sha256',
    iterations: 2,
    minPasswordlength: 32,
    saltBits: 256,
  },
  ttl: 0,
  timestampSkewSec: 0,
  localtimeOffsetMsec: 0,
}).then((sealed) => {
  console.log('unseal - aes256cbc:', sealed);
});
