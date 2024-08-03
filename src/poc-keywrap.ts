import { randomBytes } from 'crypto';
import { AES256KeyWrap } from './cryptography';

const wrapper = new AES256KeyWrap();
const kek = wrapper.generateKey();
const protectedKey = randomBytes(16);
const wrongKek = wrapper.generateKey();
const encryptedKey = wrapper.encrypt(protectedKey, kek);
const decryptedKey = wrapper.decrypt(encryptedKey, wrongKek);
console.log('input: %s', protectedKey.toString('hex'));
console.log('output: %s', decryptedKey.toString('hex'));
