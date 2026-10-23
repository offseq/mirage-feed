export const CSS = `/* Hallmark · custom (tuned) · Long Document in man-page register · nav N8 · footer Ft2 · light/mono/cool */
@font-face{font-family:"Plex Mono";src:url(/fonts/plex-mono-400.woff2) format("woff2");font-weight:400;font-display:swap}
@font-face{font-family:"Plex Mono";src:url(/fonts/plex-mono-600.woff2) format("woff2");font-weight:600;font-display:swap}
:root{
--paper:oklch(97.6% .007 85);--paper-2:oklch(94.6% .009 85);--ink:oklch(23% .022 255);--ink-2:oklch(45% .02 255);
--rule:oklch(85% .012 85);--accent:oklch(47% .085 222);--accent-soft:oklch(84% .035 222);--focus:oklch(55% .15 230);
--error:oklch(48% .15 28);--tlp-bg:#000;--tlp-fg:#fff;
--font-mono:"Plex Mono",ui-monospace,"SF Mono",Menlo,monospace;
--space-1:.25rem;--space-2:.5rem;--space-3:1rem;--space-4:1.5rem;--space-5:2.5rem;--space-6:4rem;
--indent:clamp(2ch,6vw - 1ch,7ch);--sheet:92ch;--ease-out:cubic-bezier(.2,.7,.2,1);--dur:120ms;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){
--paper:oklch(20.5% .022 252);--paper-2:oklch(24.5% .024 252);--ink:oklch(91% .012 85);--ink-2:oklch(72% .018 250);
--rule:oklch(35% .022 252);--accent:oklch(79% .085 212);--accent-soft:oklch(40% .045 222);--focus:oklch(82% .12 212);--error:oklch(75% .13 30)}}
:root[data-theme=dark]{--paper:oklch(20.5% .022 252);--paper-2:oklch(24.5% .024 252);--ink:oklch(91% .012 85);--ink-2:oklch(72% .018 250);
--rule:oklch(35% .022 252);--accent:oklch(79% .085 212);--accent-soft:oklch(40% .045 222);--focus:oklch(82% .12 212);--error:oklch(75% .13 30)}
*,*::before,*::after{box-sizing:border-box}
html,body{overflow-x:clip}
html{-webkit-text-size-adjust:100%;text-size-adjust:100%}
body{margin:0;background:var(--paper);color:var(--ink);font:400 15px/1.6 var(--font-mono);font-variant-numeric:tabular-nums}
@media (min-width:48em){body{font-size:16px}}
.sheet{max-width:var(--sheet);margin:0 auto;padding:var(--space-4) 16px var(--space-6)}
a{color:var(--accent);text-decoration:underline;text-decoration-thickness:1px;text-underline-offset:.2em}
a:hover{text-decoration-thickness:2px}
:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
.skip{position:absolute;left:-999px}
.skip:focus{left:16px;top:var(--space-2);background:var(--paper);padding:var(--space-1) var(--space-2)}
.run{display:flex;flex-wrap:wrap;justify-content:space-between;gap:var(--space-1) var(--space-3);align-items:center;color:var(--ink-2)}
.run b{color:var(--ink);font-weight:600}
.tlp{background:var(--tlp-bg);color:var(--tlp-fg);font-weight:600;padding:0 .6ch;outline:1px solid var(--rule);white-space:nowrap}
.preview{border:1px dashed var(--ink-2);padding:0 .6ch;margin-left:1ch;white-space:nowrap}
nav.toc{display:flex;flex-wrap:wrap;gap:0 2ch;margin:var(--space-3) 0 0;padding-bottom:var(--space-3);border-bottom:1px solid var(--rule)}
nav.toc a{white-space:nowrap}
main{margin-top:var(--space-4);min-width:0}
h1,h2,h3{font:600 1em/1.6 var(--font-mono);margin:0;font-style:normal}
h1,h2{text-transform:uppercase;letter-spacing:.04em;margin-top:var(--space-5)}
h3{margin-top:var(--space-4)}
section{padding-left:var(--indent);min-width:0}
section>h1,section>h2{margin-left:calc(-1 * var(--indent))}
p{margin:var(--space-2) 0 0;max-width:76ch}
ul,ol{margin:var(--space-2) 0 0;padding-left:3ch;max-width:74ch}
li+li{margin-top:var(--space-1)}
code,pre,kbd,samp{font:inherit}
.dim{color:var(--ink-2)}
.name{font-size:1.0625em}
.cmd{display:flex;align-items:flex-start;gap:var(--space-2);margin-top:var(--space-3);border-left:2px solid var(--accent);padding:var(--space-2) var(--space-3);background:var(--paper-2)}
.cmd code,.sel{user-select:all;-webkit-user-select:all;overflow-wrap:anywhere;min-width:0;flex:1}
.cmd .p{user-select:none;-webkit-user-select:none;color:var(--ink-2)}
pre{margin:var(--space-3) 0 0;padding:var(--space-3);background:var(--paper-2);border-left:2px solid var(--rule);overflow-x:auto;line-height:1.5;max-width:100%}
.copy{font:inherit;font-size:.8125em;color:var(--ink-2);background:transparent;border:1px solid var(--rule);padding:0 .8ch;cursor:pointer;white-space:nowrap;transition:color var(--dur) var(--ease-out),border-color var(--dur) var(--ease-out)}
.copy:hover{color:var(--ink);border-color:var(--ink-2)}
.copy:active{transform:translateY(1px)}
.copy[data-state=done]{color:var(--accent);border-color:var(--accent)}
.copy[data-state=fail]{color:var(--error);border-color:var(--error)}
.big{font-size:clamp(2.25rem,7vw,4rem);font-weight:600;line-height:1.1;letter-spacing:-.02em;margin-top:var(--space-3)}
.lede{margin-top:var(--space-1);color:var(--ink-2)}
.gap{display:block;width:100%;height:1.5rem;margin-top:var(--space-3);outline:1px solid var(--ink-2);outline-offset:-1px}
.gap .pub{fill:var(--accent)}
.gap .obs{fill:url(#hatch)}
.gap .hl{stroke:var(--ink-2);stroke-width:1}
.legend{display:flex;flex-wrap:wrap;gap:0 3ch;margin-top:var(--space-2);color:var(--ink-2)}
.legend i{display:inline-block;width:1.4ch;height:.8em;margin-right:1ch;vertical-align:-.05em;background:var(--accent)}
.legend i.h{background:repeating-linear-gradient(135deg,var(--ink-2) 0 1px,transparent 1px 4px);outline:1px solid var(--ink-2)}
.scroll{overflow-x:auto;max-width:100%;margin-top:var(--space-3)}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:var(--space-1) 2ch var(--space-1) 0;border-bottom:1px solid var(--rule);vertical-align:top}
th{font-weight:600;color:var(--ink-2)}
th:last-child,td:last-child{padding-right:0}
.n{text-align:right;white-space:nowrap}
.nw{white-space:nowrap}
.used{display:block;white-space:normal;font-size:.8125em;color:var(--ink-2)}
abbr[title]{text-decoration:none;cursor:help}
td.bar{width:40%;min-width:6ch;vertical-align:middle}
.bar svg{display:block;width:100%;height:.7em}
.bar .t{fill:var(--paper-2)}
.bar .v{fill:var(--accent)}
.tops{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,32ch),1fr));gap:0 4ch}
.tops>:first-child{grid-column:1/-1}
.tops h3{color:var(--ink-2);font-weight:400}
details{border-bottom:1px solid var(--rule)}
details:first-of-type{border-top:1px solid var(--rule);margin-top:var(--space-3)}
summary{cursor:pointer;list-style:none;padding:var(--space-2) 0}
summary::-webkit-details-marker{display:none}
summary::before{content:"[+] ";color:var(--ink-2)}
details[open]>summary::before{content:"[-] "}
summary:hover{color:var(--accent)}
details>:last-child{margin-bottom:var(--space-3)}
.empty{border:1px dashed var(--rule);padding:var(--space-3);margin-top:var(--space-3);color:var(--ink-2)}
.cta{display:inline-block;margin-top:var(--space-4);padding:var(--space-2) 2ch;background:var(--ink);color:var(--paper);text-decoration:none;font-weight:600;white-space:nowrap}
.cta:hover{background:var(--accent);color:var(--paper)}
.cta:active{transform:translateY(1px)}
form{margin-top:var(--space-3);max-width:60ch}
label{display:block;margin-top:var(--space-3);font-weight:600}
label .dim{font-weight:400}
input,textarea{display:block;width:100%;margin-top:var(--space-1);font:inherit;color:var(--ink);background:var(--paper-2);border:1px solid var(--rule);border-radius:0;padding:var(--space-2)}
input:hover,textarea:hover{border-color:var(--ink-2)}
input:focus-visible,textarea:focus-visible{border-color:var(--focus)}
input[aria-invalid=true]{border-color:var(--error)}
textarea{min-height:7em;resize:vertical}
.hp,.sr{position:absolute;left:-999px;width:1px;height:1px;overflow:hidden}
button[type=submit]{margin-top:var(--space-4);font:inherit;font-weight:600;color:var(--paper);background:var(--ink);border:0;padding:var(--space-2) 2ch;cursor:pointer;white-space:nowrap}
button[type=submit]:hover{background:var(--accent)}
button[type=submit]:active{transform:translateY(1px)}
button[type=submit]:disabled{opacity:.55;cursor:progress}
.msg{margin-top:var(--space-3);padding:var(--space-2) var(--space-3);border-left:2px solid var(--accent)}
.msg.err{border-color:var(--error);color:var(--error)}
.ph{background:var(--paper-2);outline:1px dashed var(--ink-2);padding:0 .5ch}
footer{margin-top:var(--space-6);padding-top:var(--space-3);border-top:1px solid var(--rule)}
footer p{max-width:none;color:var(--ink-2)}
footer .run{margin-top:var(--space-3)}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
@media print{nav.toc,.copy,.cta{display:none}}
`;
