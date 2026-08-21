import express from 'express';
import crypto from 'node:crypto';
import { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } from '@simplewebauthn/server';

const app = express();
app.use(express.json({ limit: '32kb' }));
const PORT = Number(process.env.PORT || 3000);
const RP_ID = process.env.RP_ID || 'localhost';
const ORIGIN = process.env.ORIGIN || `http://localhost:${PORT}`;
const RP_NAME = process.env.RP_NAME || 'DialysisSafe';
const COOKIE_NAME = 'dialysis_safe_session';
const credentials = new Map();
const challenges = new Map();
const sessions = new Set();
function base64url(buffer){return Buffer.from(buffer).toString('base64url');}
function randomToken(){return base64url(crypto.randomBytes(32));}
function readCookie(req,name){const row=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(`${name}=`));return row?decodeURIComponent(row.slice(name.length+1)):null;}
function isAuthenticated(req){return sessions.has(readCookie(req,COOKIE_NAME));}
function setSession(res){const token=randomToken();sessions.add(token);res.setHeader('Set-Cookie',`${COOKIE_NAME}=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=28800`);}
function requireSession(req,res,next){if(!isAuthenticated(req))return res.status(401).json({error:'Passkey authentication required'});next();}
app.get('/',(req,res)=>res.redirect(isAuthenticated(req)?'/index.html':'/auth.html'));
app.get('/api/auth/status',(req,res)=>res.json({configured:Boolean(RP_ID&&ORIGIN),enrolled:credentials.size>0,authenticated:isAuthenticated(req)}));
app.post('/api/auth/register/options',async(req,res)=>{const username=String(req.body?.username||'').trim().slice(0,80);if(!username)return res.status(400).json({error:'Username is required'});const userID=base64url(crypto.createHash('sha256').update(username).digest());const options=await generateRegistrationOptions({rpName:RP_NAME,rpID:RP_ID,userName:username,userID,attestationType:'none',excludeCredentials:[...credentials.values()].filter(c=>c.username===username).map(c=>({id:c.id})),authenticatorSelection:{residentKey:'required',userVerification:'required'}});challenges.set(`reg:${username}`,options.challenge);res.json(options);});
app.post('/api/auth/register/verify',async(req,res)=>{const username=String(req.body?.username||'').trim().slice(0,80),expectedChallenge=challenges.get(`reg:${username}`);if(!expectedChallenge)return res.status(400).json({error:'Registration challenge expired'});try{const verification=await verifyRegistrationResponse({response:req.body.response,expectedChallenge,expectedOrigin:ORIGIN,expectedRPID:RP_ID,requireUserVerification:true});if(!verification.verified||!verification.registrationInfo)return res.status(400).json({error:'Passkey registration failed'});const info=verification.registrationInfo;credentials.set(info.credential.id,{id:info.credential.id,publicKey:info.credential.publicKey,counter:info.credential.counter,username});challenges.delete(`reg:${username}`);setSession(res);res.json({verified:true});}catch(error){res.status(400).json({error:error.message});}});
app.post('/api/auth/login/options',async(_req,res)=>{const options=await generateAuthenticationOptions({rpID:RP_ID,userVerification:'required',allowCredentials:[...credentials.values()].map(c=>({id:c.id,type:'public-key'}))});challenges.set('login',options.challenge);res.json(options);});
app.post('/api/auth/login/verify',async(req,res)=>{const expectedChallenge=challenges.get('login'),credential=credentials.get(req.body?.response?.id);if(!expectedChallenge)return res.status(400).json({error:'Login challenge expired'});if(!credential)return res.status(401).json({error:'Unknown passkey'});try{const verification=await verifyAuthenticationResponse({response:req.body.response,expectedChallenge,expectedOrigin:ORIGIN,expectedRPID:RP_ID,credential:{id:credential.id,publicKey:credential.publicKey,counter:credential.counter},requireUserVerification:true});if(!verification.verified)return res.status(401).json({error:'Passkey verification failed'});credential.counter=verification.authenticationInfo.newCounter;challenges.delete('login');setSession(res);res.json({verified:true,username:credential.username});}catch(error){res.status(401).json({error:error.message});}});
app.post('/api/auth/logout',(req,res)=>{const token=readCookie(req,COOKIE_NAME);if(token)sessions.delete(token);res.setHeader('Set-Cookie',`${COOKIE_NAME}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`);res.json({ok:true});});
app.get('/api/secure-config-check',requireSession,(_req,res)=>res.json({ok:true,message:'Authenticated server endpoint is working. Secrets remain server-side.'}));
app.use(express.static('.',{index:false}));
app.listen(PORT,()=>console.log(`DialysisSafe listening on ${ORIGIN}`));
