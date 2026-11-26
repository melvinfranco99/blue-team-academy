"""Genera la narración MP3 de cada escena con Piper (voz es_ES-davefx-medium).
Uso: python tools/generar_audio.py narr.json ruta/voz.onnx
Escribe assets/audio/<clave>.mp3 y assets/audio/manifest.js (duración y comienzo de cada frase)."""
import json, os, subprocess, sys
from piper import PiperVoice
from piper.config import SynthesisConfig

ROOT = os.path.join(os.path.dirname(__file__), '..')
OUT = os.path.join(ROOT, 'assets', 'audio')
narr = json.load(open(sys.argv[1]))
voice = PiperVoice.load(sys.argv[2])
cfg = SynthesisConfig(length_scale=1.04)
SR = voice.config.sample_rate
LEAD, GAP = int(0.2 * SR), int(0.32 * SR)
manpath = os.path.join(OUT, 'manifest.json')
man = json.load(open(manpath)) if os.path.exists(manpath) else {}
todo = [k for k in narr if not (k in man and os.path.exists(os.path.join(OUT, k + '.mp3')))]
print(f'{len(narr)} escenas, {len(todo)} por generar', flush=True)
for n, k in enumerate(todo, 1):
    pcm, starts = bytearray(b'\0\0' * LEAD), []
    for i, s in enumerate(narr[k]):
        starts.append(round(len(pcm) / 2 / SR, 2))
        for ch in voice.synthesize(s, syn_config=cfg):
            pcm += ch.audio_int16_bytes
        pcm += b'\0\0' * GAP
    subprocess.run(['ffmpeg', '-loglevel', 'error', '-y', '-f', 's16le', '-ar', str(SR), '-ac', '1', '-i', '-',
                    '-c:a', 'libmp3lame', '-b:a', '40k', os.path.join(OUT, k + '.mp3')], input=bytes(pcm), check=True)
    man[k] = [round(len(pcm) / 2 / SR, 2), starts]
    if n % 25 == 0 or n == len(todo):
        json.dump(man, open(manpath, 'w'))
        print(f'{n}/{len(todo)}', flush=True)
man = {k: v for k, v in man.items() if k in narr}
json.dump(man, open(manpath, 'w'))
with open(os.path.join(OUT, 'manifest.js'), 'w') as f:
    f.write('window.NARR=' + json.dumps(man, separators=(',', ':')) + ';\n')
print('total', round(sum(v[0] for v in man.values()) / 60, 1), 'min')
