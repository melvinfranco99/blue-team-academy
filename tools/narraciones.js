/* Vuelca la narración de todas las escenas (clave = hash FNV-1a del texto) en JSON.
   Uso: node tools/narraciones.js > /tmp/narr.json */
const fs = require('fs'), path = require('path');
const root = path.join(__dirname, '..');
const src = fs.readFileSync(path.join(root, 'assets/js/player.js'), 'utf8');
const sentences = eval('(' + src.match(/const sentences = (s => \{[\s\S]*?\n  \});/)[1] + ')');
const narrKey = eval('(' + src.match(/const narrKey = (s => \{[\s\S]*?\});/)[1] + ')');
global.window = global; global.VIDEOS = [];
const d = path.join(root, 'assets/js/videos/');
const html = fs.readFileSync(path.join(root, 'videos.html'), 'utf8');
for (const m of html.matchAll(/assets\/js\/videos\/([\w-]+\.js)/g)) eval(fs.readFileSync(d + m[1], 'utf8'));
const out = {};
for (const v of VIDEOS) for (const s of v.scenes) if (s.say) out[narrKey(s.say)] = sentences(s.say).map(x => x.replace(/`/g, '').replace(/\*\*/g, ''));
process.stdout.write(JSON.stringify(out));
