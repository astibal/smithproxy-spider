# H2 translate: první živé napojení (API 0.6)

**Experimentální, omezený rozsah.** API už prochází běžným backendem a jeho
sandboxovanými workery. Není to kompletní H2 terminátor ani transparentní
podpora všech HTTP/2 spojení. Nepodporovaný stav se odmítá, neobchází.

## Spuštění

1. Proxy musí obsahovat webhook control patch a posílat v content metadatech
   `webhook_control: {version: 1, mode: "regular"|"strict", sequence: N}`.
   `sequence` počítá content callbacky celého spojení, společně pro oba směry.
2. Python worker potřebuje `python-hpack`. Bez něj dál funguje rewrite,
   ale translate vyvolá CommitException.
3. Povol jediný deployment s instanciací `flow`. Scope a session filter určují
   přijetí nového spojení; aktivovat lze jen v prvním callbacku (`sequence == 1`).
4. Vytvoř nové spojení. Skript musí v každém callbacku vrátit translate výsledek:

<!-- translate-example: replace-header -->
```python
for part in api.message.parts:
    if part.type == PartType.Http2.Header:
        part.headers.set_header(b"x-lab", b"spider")
return api.message.translate()
```

I když není co změnit:

<!-- translate-example: unchanged -->
```python
return api.message.translate()
```

## Příklady: indexovaná hlavička a explicitní překlad

Nejde o zápis číselného indexu jako v rewrite režimu. Aktivní translate předá
skriptu rozbalené jméno a hodnotu; výstupní indexování obstará vlastní encoder.
Stejný `set_header()` tedy funguje i tehdy, když na drátu přišel jen index.

Příklad pro testovací endpoint: změň `x-lab` pouze ve druhém klientském callbacku.
První callback aktivuje překlad a naplní vstupní tabulku. V tomto malém scénáři
každý klientský callback obsahuje jeden HEADERS blok; obecně callback není request.

<!-- translate-example: indexed-once -->
```python
if api.side == "L":
    turn = api.state.get("client_callbacks", 0) + 1
    api.state["client_callbacks"] = turn

    if turn == 2:
        for part in api.message.parts:
            if part.type == PartType.Http2.Header:
                part.headers.set_header(b"x-lab", b"changed")

# I třetí callback musí překládat, přestože už nic neměníme.
return api.message.translate()
```

| Callback | Vstup odesílatele | Hodnota u příjemce |
| --- | --- | --- |
| 1 | literal `x-lab: original`, uložený do tabulky | `x-lab: original` |
| 2 | dynamický index 62 (`be`) | `x-lab: changed` |
| 3 | znovu index 62 (`be`) | `x-lab: original` |

Index 62 zde plyne z konkrétního testovacího vstupu, není to pevné číslo této
hlavičky. Skript index vůbec neřeší. Tabulky jsou oddělené po směrech, proto ani
odpověď serveru nemusí mít stejné indexy. Protisměr také vždy zavolá translate.

### Chybný příklad: „tentokrát nic neměním, tak nemusím překládat“

Následující skript je **záměrně špatně** pro již aktivní translate:

<!-- translate-example: missing-translate -->
```python
return None
```

Worker odmítne výsledek: chybí explicitní `api.message.translate()`. Backend
vrátí 503 a strict proxy spojení zavře. Ani `return api.message.commit()` tuto
povinnost nenahrazuje; to je lokální rewrite, ne pokračování HPACK překladu.

Tyto označené příklady test čte přímo z dokumentace a spouští v sandboxovaných
workerech. U indexovaného scénáře ověřuje skutečné `be` na vstupu a výsledné
hodnoty nezávislým libnghttp2 dekodérem, nikoli jen návratový status.

**Žádné rozhodování engine, zda se skript vyplatí spustit.** Aktivní spojení
projde při každém content callbacku svým skriptem, včetně DATA, SETTINGS/PING
a opačného směru. Filtr, scope, GUI rozhodnutí a heavy-traffic cutoff už ho
nesmějí tiše vynechat. Skript lze vevnitř větvit, ale musí vrátit translate.

## Stav a selhání

- Backend připne spojení k deployment ID a verzi. Další deploymenty mu do toku
  nevstupují. HPACK tabulky jsou samostatné pro vstup/výstup a L/R.
- Stav se přenáší jako omezený JSON checkpoint, ne pickle ani Python globals.
  Worker může být mezi callbacky jiný. Limit je 64 KiB na směr; checkpointy
  vstupují také do deployment limitu 4 MiB společně s user state a holdem.
- První úspěšný výsledek obsahuje `control.mode=strict` spolu s replacementem.
  Nová proxy aplikuje control před replacementem. Další callback musí potvrdit
  strict a přesně navazující sequence. Jde o capability + stavovou kontrolu,
  nikoli samostatný round-trip handshake před prvním přepisem.
- Chyba, timeout, přetížení, `return None`, chybějící translate, expirovaný stav,
  vypnutí/redeploy skriptu nebo mezera v sequence znamenají HTTP 503. Strict
  proxy spojení zavře bez propuštění aktuálního obsahu. Backend si ponechá
  neúspěšné připnutí až do connection-stop; nepokouší se začít tabulky znovu.
- Strict callback bez známého připnutí (například po restartu Spideru) je také
  odmítnut. Chybějící capability na staré proxy nikdy nepovolí první překlad.
- Tabulky nejsou publikovány do GUI ani do uživatelského `api.state`.
  Úspěch přípravy není odeslání: teprve návrat výsledku ze skriptu je publikuje.

## Co tento první krok ještě neumí

- hold/reassembly v translate, neúplné frame/header bloky a PUSH_PROMISE;
- změny DATA nebo control rámců, vložení/mazání/přeskládání Parts;
- raw HPACK a explicitní manipulace s indexy (to zůstává rewrite);
- SETTINGS měnící kapacitu HPACK tabulky z 4096 nebo max frame size z 16384;
- převzetí již rozběhlého spojení, více aktivních překladových deploymentů,
  živý návrat přeloženého spojení do rewrite;
- garanci HTTP sémantiky uživatelem změněných hlaviček. Překládá se HPACK stav,
  nejde o automatickou opravu libovolně pozměněného aplikačního protokolu.

Známá H2 preface a nezměněné DATA/control frames projdou byte-for-byte.
Přípustné defaultní SETTINGS se explicitně zpracují skriptem a předají nezměněné.
Output encoder vlastní indexování; `never` zůstává never-indexed.

## Ověření

`inspection_translate_worker_tests` obnovuje checkpoint v novém sandboxovaném
procesu po každé zprávě a kontroluje výsledek nezávislým libnghttp2 dekodérem.
`inspection_translate_live_tests` používá skutečný backend handler a worker pool:
filtr přestane odpovídat, DATA i opačný směr přesto spouštějí skript; testuje
vynechané translate, vypnutí, ztracený stav, starou proxy a chybějící callback.
Původní POC přidává negativní kontrolu a dlouhou sérii indexů/eviction.

```sh
cmake -S . -B build -DSPIDER_TEST_TRANSLATE_POC=ON
cmake --build build -j 2
ctest --test-dir build --output-on-failure
```

Proxy control/sequence se zvlášť ověřuje jejími JSON a SXBN integračními testy.
Tyto dvě produktové vrstvy zatím netvoří jeden automatický end-to-end test
s oběma živými procesy najednou. Žádné nasazení do lab1 se neprovádělo.

Lokální ověření 2026-10-25: build úspěšný, všech 25 CTest sad Spideru prošlo
(32,34 s), včetně tří translate sad. Proxy prošla pěti control/need-more sadami
(28,47 s). Generované API příklady odpovídají schématu; `git diff --check` čistý.
