# TODO

## Scripting

- **Hold + fail-open (vědomě odloženo):** po `need-more` má dřívější bajty pouze
  Spider. Výpadek Spideru/proxy, timeout, přetížení fronty či změna deploymentu
  mohou pustit aktuální fragment bez zadrženého prefixu. Řešit ochranu pořadí
  a úplnosti také pro HOLD/REWRITE, nejen TRANSLATE; zatím zachovat fail-open.
  Navrhnout strict/drop řízení a obnovu/potvrzení vlastnictví dat, nikoli jen
  ukládání bufferu na disk. Stejně dořešit disable/redeploy, změnu filtru,
  automatické suspendování, idle expiry, limity a ukončení spojení s holdem.
- Rozšířit živý hold z posledního zapnutého flow deploymentu na libovolnou
  pozici v řetězci; vyřešit transakce prefixu a rollback mezi skripty.
- Rozšířit H1 Parts na neúplné hlavičky, chunked, komprimované a pipelinované
  zprávy. U H2 doplnit frame header rozdělený mezi callbacky (méně než 9 bajtů).

- Stabilize a richer, typed Python API without exposing raw webhook JSON.
- Add a browsable cookbook ranging from simple payload logging to stateful session analysis.
- Support replaying complete captured sessions through scripts.
- Add explicit script capabilities and separate observe, transform, control, and offline modes.
- Persist backend inspection deployments and traffic rules across server restarts; introduce reusable Python workers after measuring per-callback process overhead.
