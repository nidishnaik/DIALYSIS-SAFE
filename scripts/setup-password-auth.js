import fs from 'node:fs/promises';
import crypto from 'node:crypto';
import readline from 'node:readline';

function ask(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question, (answer) => { rl.close(); resolve(answer.trim()); });
  });
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 32);
  return `scrypt$${salt.toString('base64url')}$${hash.toString('base64url')}`;
}

const username = await ask('Username: ');
if (!username) throw new Error('Username cannot be empty.');
const password = await ask('Password: ');
if (!password) throw new Error('Password cannot be empty.');

const existing = await fs.readFile('.env', 'utf8').catch(() => '');
const lines = existing.split(/\r?\n/).filter(line =>
  !line.startsWith('AUTH_USERNAME=') && !line.startsWith('AUTH_PASSWORD_HASH=')
);
lines.push(`AUTH_USERNAME=${username}`);
lines.push(`AUTH_PASSWORD_HASH=${hashPassword(password)}`);
await fs.writeFile('.env', `${lines.filter(Boolean).join('\n')}\n`, { mode: 0o600 });
console.log('Password login configured in .env.');
console.log('The .env file is ignored by Git and must not be committed.');
