#!/usr/bin/env python3
"""End-to-end genuine verification: run all 100 guards in chain order with the
independently derived answers, checking acceptance + token chain continuity."""
import subprocess, re, sys

ANS = {
1:'xc8lsn3wb',2:'388kwq9zg8',3:'hlig8wx9',4:'oh31aua8u',5:'8tog1wztme',6:'zb7ovq04',
7:'ztyxz2z3t',8:'57gi3ei1eo',9:'n2cr2wmr',10:'6k3cb3xn8',11:'x5d33otflg',12:'om0vaedx',
13:'dfsn4itit',14:'bjvhlzcckl',15:'7ex81rur',16:'prt580hhb',17:'k25dmbesbq',18:'o1vpw7qz',
19:'fjrzcjf1z',20:'n59y2eimab',21:'xcegippj',22:'b7byz243z',23:'dvuiy8f39f',24:'i2wkg9qu',
25:'7b78s3t4i',26:'9c7zpsyb5r',27:'huvreh7j',28:'hvgd83o0o',29:'pm29cq9qgg',30:'0zz8r4kn',
31:'qbwu901wd',32:'iaosuisqjz',33:'9mw3ujdg',34:'gkdu5mqo1',35:'edojn13dmd',36:'3zestcao',
37:'lltxnq91v',38:'nsd34ctxid',39:'tysjxzr2',40:'hf8ok6vph',41:'2ut9bfu2y8',42:'6t2phrtk',
43:'bjmuyvlha',44:'99w8ehig7z',45:'wh6cdf8o',46:'2pf1ni1iy',47:'06cztpk2r9',48:'ar3lku5k',
49:'k3hvofyyr',50:'45i4yt6iee',51:'p3u0qais',52:'a7rv63b3t',53:'nffm8klkm4',54:'mfxtsrga',
55:'nyz0d6gla',56:'81mx7kg4x3',57:'v3n6qdo8',58:'1e5jdxzpe',59:'hh7n6p8825',60:'pspmt280',
61:'9uiibzj5x',62:'640mvx1d5y',63:'wenao8dq',64:'618o8buuz',65:'l7s0d18g7k',66:'90c1yof7',
67:'eik39pge4',68:'xf1ijr3xh3',69:'wjipmqa2',70:'ll0kxho2w',71:'lqnpfjn0ks',72:'4zukgwh7',
73:'e8okpa80s',74:'q1egor4nac',75:'ctxxfm5d',76:'nhl7rz0gr',77:'d2mdcyq1ge',78:'qdvmyynm',
79:'vjt61h24s',80:'53lxqjzwmw',81:'bov1k8zg',82:'gc11y5bat',83:'l8905nzisz',84:'f8blivuq',
85:'ab507xk7r',86:'2hwarfwmxr',87:'oz3kunvq',88:'evxw8ed7y',89:'ahbcspjco8',90:'ijcg3b7n',
91:'8gkevz3ru',92:'xcreo6xp19',93:'p0ko8m5y',94:'xcmod8k3q',95:'pkkw1327y3',96:'eaapuvz6',
97:'yndy28278',98:'9yfhzhnz0l',99:'lwgravmh',100:'1wf42a9ei',
}
ART = {10:'artifact04.bin', 94:'artifact24.bin', 97:'artifact46.bin', 99:'artifact68.bin'}
token = '66b53e79aa2f91796326c08ed6e43607'
ok = 0
for n in range(1, 101):
    g = 'guard%02d.vmb' % n
    cmd = ['./vmcore', g, token] + ([ART[n]] if n in ART else [])
    p = subprocess.run(cmd, input=ANS[n] + '\n', capture_output=True, text=True, timeout=20, cwd='original')
    out = p.stdout + p.stderr
    m = re.search(r'token: ([0-9a-f]{32})', out)
    acc = '[+] guard accepted.' in out
    fm = re.search(r'FINAL FLAG: (\S+)', out)
    extra = ''
    if 'BAND COMPLETE' in out: extra = ' [BAND COMPLETE]'
    if fm: extra = ' [FINAL FLAG: %s]' % fm.group(1)
    if not acc or not m:
        print('guard%02d FAILED' % n); print(out); break
    ok += 1
    print('guard%02d accepted tok=%s%s' % (n, m.group(1), extra))
    token = m.group(1)
print('TOTAL ACCEPTED: %d/100' % ok)
