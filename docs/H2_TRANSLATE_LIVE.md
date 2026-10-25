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

### Neúplný rámec nebo HEADERS/CONTINUATION přes více callbacků

<!-- translate-example: hold-incomplete -->
```python
for part in api.message.parts:
    if not part.complete:
        api.message.parts.hold_from(part)
        break

    if part.type == PartType.Http2.Header:
        part.headers.set_header(b"x-lab", b"changed")

return api.message.translate()
```

Skript sám určuje hranici holdu. Kompletní prefix se přeloží a odešle, suffix
zůstane jako typované Parts. Prázdný prefix vrací `need-more` a současně zapíná
nebo zachovává strict policy. Další callback ve stejném směru doplní neúplný
rámec/blok; protisměr má vlastní hold i HPACK tabulky a dál spouští svůj callback.

HPACK checkpoint reprezentuje jen **odeslaný prefix**. Hlavičky v holdu sice
mohou mít dekódovaný pohled pro skript, ale neposouvají trvale tabulky. U kompletní
podržené hlavičky přežijí logické změny; neúplnou část nejprve dosbírej, před
holdu ji neupravuj. Opětovné spuštění tvého skriptu může tvoje změny zopakovat:
u ne-idempotentních úprav si to ohlídej pomocí vlastního stavu.

Dokud není celá devítibajtová hlavička rámce, je fragment reprezentovaný jako
`PartType.Opaque` s `complete == False`; není ještě známý ani jeho stream ID.
Podobně lze podržet prefix H2 preface. Toto rámování platí pro aktivní H2 translate,
není to obecné odhadování protokolu u libovolných opaque dat. První aktivace stále
vyžaduje H2 preface (případně její prefix) nebo H2 anotaci od proxy.

`api.message.bytes` dál obsahuje aktuální callback; celé obnovené zobrazení je
v `api.message.parts`. Hold je omezený existujícím 1 MiB limitem serializovaného
checkpointu a 4 MiB deployment kvótou; obnova nad 1 MiB vstupních bajtů se odmítá.
Překročení limitu v aktivním translate je chyba a spojení se zavře, nikoliv bypass.

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
  Společný SETTINGS checkpoint má navíc limit 16 KiB.
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

## SETTINGS a potvrzení limitů

### Explicitní režim a trvalý limit

```python
api.connection.set_mode(Mode.Translate)
api.connection.http2.enforce_header_table_limit(0)

for part in api.message.parts:
    if not part.complete:
        api.message.parts.hold_from(part)
        break

return api.message.translate()
```

Obě volání jsou idempotentní a pouze připravují záměr. První vyžaduje flow
instanciaci a způsobilé živé H2 spojení. Druhé nastaví stálý maximální limit
pro oba směry. Vynechání návratu `message.translate()` po `set_mode()` je chyba;
nic se nepublikuje. Původní aktivace samotným `message.translate()` zůstává
kompatibilní. `Mode.Rewrite` nelze použít pro návrat již přeloženého spojení.

Politika omezuje budoucí SETTINGS a nikdy nezvýší menší limit oznámený peerem.
Pokud už handshake proběhl, může vložit vlastní SETTINGS; jeho ACK spotřebuje
engine a nepředá ho protistraně jako potvrzení jejího požadavku. Původní ACK
nadále procházejí. Opakované stejné nastavení negeneruje další rámce.

Každý směr politiku dostane při nejbližším způsobilém callbacku, až po jeho
prvním SETTINGS. Samostatné vložení čeká také na uvolnění holdu. Není to okamžitý
broadcast do obou socketů ani background task. Nula zakáže dynamickou tabulku,
nikoli statické indexy nebo Huffman. Po `translate()` už settery volat nelze.

SETTINGS i ACK nadále procházejí explicitním `return api.message.translate()`.
Rámce se předávají beze změny; skript nepotřebuje zvláštní volání pro jejich
zpracování. SETTINGS odeslané z R nastavují omezení pro L a naopak.

- Každý směr má FIFO frontu nejvýše 64 čekajících SETTINGS, včetně prázdných
  nebo těch s neznámými identifikátory. ACK potvrzuje nejstarší položku.
- Nový limit se při kontrole vstupu uplatní po ACK. Před ním mohou ještě přijít
  data podle starých limitů. ACK bez čekajícího SETTINGS je chyba.
- Zmenšení HPACK tabulky vyžaduje odpovídající table-size update v následujícím
  header bloku. Při zmenšení a zvětšení se zachová nejmenší mez i konečná hodnota.
- Vstupní dekodér respektuje oznámenou kapacitu; stále platí velikostní kvóty
  checkpointu. Výstupní encoder používá nejvýše 4096 bajtů tabulky, i když peer
  povolí více. To je legální menší kapacita, nikoliv limit peerova vstupu.
- MAX_FRAME_SIZE řídí kontrolu vstupních rámců i dělení výstupních
  HEADERS/CONTINUATION. Změna se může potvrdit uprostřed jednoho callbacku.
- Zadržený SETTINGS/ACK nemění publikovaný stav. Ten se posune až spolu
  s emitovaným prefixem. Neúspěšný commit nepublikuje nic.

Synchronizace vychází z [RFC 9113 §6.5.3](https://www.rfc-editor.org/rfc/rfc9113.html#section-6.5.3)
a změny HPACK kapacity z [RFC 7541 §4.2](https://www.rfc-editor.org/rfc/rfc7541.html#section-4.2).

## Co tento první krok ještě neumí

- PUSH_PROMISE;
- uživatelské změny DATA nebo control rámců, vložení/mazání/přeskládání Parts
  (výjimkou je explicitní SETTINGS politika výše);
- raw HPACK a explicitní manipulace s indexy (to zůstává rewrite);
- převzetí již rozběhlého spojení, více aktivních překladových deploymentů,
  živý návrat přeloženého spojení do rewrite;
- garanci HTTP sémantiky uživatelem změněných hlaviček. Překládá se HPACK stav,
  nejde o automatickou opravu libovolně pozměněného aplikačního protokolu.

Známá H2 preface a nezměněné DATA/control frames projdou byte-for-byte.
Bez zapnuté politiky limitu se přípustné SETTINGS explicitně zpracují skriptem
a předají nezměněné. Politika smí změnit SETTINGS a spotřebovat vlastní ACK.
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
Žádné nasazení do lab1 se neprovádělo.

### Skutečný end-to-end harness

`tests/translate_e2e.py` spouští oba produktové procesy a řízené H2 protějšky:

```text
H2 klient -- SOCKS --> Smithproxy -- TCP --> H2 origin
                          |
                          +-- content webhook --> Spider --> sandbox worker
```

Content webhook vede přímo z proxy do Spideru; žádný mock nevytváří anotace ani
replacement. Pouze discovery management API je testovací stub, který získá
náhodnou callback URL Spideru pro dočasnou konfiguraci proxy. Registraci/obnovu
lease proti skutečnému management API tento harness netestuje.

Základní scénáře ověřují:

- H2 preface, výchozí SETTINGS a ACK;
- čtyři request/response streamy se skutečným dynamickým indexem 62 na vstupu;
- změnu hlavičky jen ve druhém requestu i response a původní hodnotu v dalších;
- nezávislé dekódování výstupu pomocí libnghttp2;
- PING/ACK bez změny bajtů a přesně 14 spuštění skriptu;
- capability, strict mode a souvislou sequence uvnitř každého callbacku;
- patnáctý callback s výjimkou nebo chybějícím translate: EOF/reset na origin
  socketu, žádný propuštěný bajt a jedna zaznamenaná chyba deploymentu.

Test používá plaintext H2 na loopbacku, malé rámce a výchozí SETTINGS.
Varianta `--settings --fragmented` mění tabulky v obou směrech
`4096 → 0 → 128 → 8192`, potvrzuje je přes ACK a ověřuje výstup nezávislým
libnghttp2 dekodérem. Jednotková sada `inspection_translate_settings_tests`
navíc kontroluje pořadí ACK, stará data před ACK, chybné limity, kvótu fronty,
duplicitní změny kapacity, velké HEADERS/CONTINUATION a zadržení SETTINGS/ACK.
Varianta `--fragmented` navíc dělí HEADERS/CONTINUATION po jednotlivých bajtech,
čeká na každý callback, kontroluje ticho do dokončení bloku a testuje hotový
PING prefix i odpověď v protisměru během holdu. Jednotková sada
`inspection_translate_hold_tests` prochází všechny hranice dělení zprávy,
částečnou preface, přenos mezi čerstvými workery a zachování kompletních drafts.
Není to test TLS, dlouhodobé zátěže nebo všech H2 stavových přechodů.
Porty, konfigurace i úložiště jsou dočasné; skutečné lab instance se nemění.

```sh
python3 tests/translate_e2e.py \
  --smithproxy-source ../smithproxy-need-more-test \
  --smithproxy ../smithproxy-need-more-test/build/smithproxy \
  --spider build/smithproxy-spider --failure exception
```

Pro druhý scénář použij `--failure missing-translate`, pro fragmentaci `--fragmented`.
Pro kombinaci fragmentace a změn limitů přidej `--fragmented --settings`.
Varianta `--fragmented --policy` aktivuje nulový limit až po handshaku,
ověřuje vložené SETTINGS a spotřebování obou syntetických ACK na skutečných
socketech. Další callbacky opakují stejné nastavení bez dalších SETTINGS.
CTest registraci všech variant
zapneš spolu s `SPIDER_TEST_TRANSLATE_POC=ON` nastavením absolutních cest
`SPIDER_E2E_SMITHPROXY_SOURCE` a `SPIDER_E2E_SMITHPROXY_BINARY` při konfiguraci
CMake. Testy vyžadují loopback sockety, sandbox worker a `python-hpack`.

Lokální ověření 2026-10-25: build úspěšný, všech 25 CTest sad Spideru prošlo
(32,34 s), včetně tří translate sad. Proxy prošla pěti control/need-more sadami
(28,47 s). Generované API příklady odpovídají schématu; `git diff --check` čistý.

Po přidání skutečného E2E: všech 27 sad Spideru prošlo (41,09 s), včetně obou
variant selhání. Samostatně každá E2E varianta prošla třikrát za sebou (celkem
6/6 běhů, 23,43 s). Proxy control/need-more regrese opět 5/5 (28,47 s).
Testovaná proxy obsahuje commit `ddb5ce1` nad `412680e`.

Po doplnění translate hold/reassembly: všech 29 sad prošlo (58,99 s).
Nová hold sada obsahuje devět testů včetně všech hranic dělení testovací zprávy,
jednotlivých bajtů a atomických chyb. Fragmentovaný E2E potvrdil přesně 225
úspěšných explicitních callbacků v obou směrech a zavření bez úniku při následné
výjimce. Samostatně prošel i live test prvního `need-more` s aktivací strict.

Po doplnění SETTINGS/ACK: všech 31 sad prošlo (83,64 s), včetně čtyř skutečných
E2E variant. Nová SETTINGS sada obsahuje devět testů; worker sada navíc ověřuje
společný stav protisměrů mezi čerstvými sandboxovanými procesy. SETTINGS E2E
prošel s fragmentací HEADERS/CONTINUATION, evikcí a opětovným růstem tabulek
a nezávislým libnghttp2 dekodérem (21,95 s). Build, kontrola generovaných API
příkladů i `git diff --check` prošly. Proxy zůstává na `ddb5ce1`, beze změn.

Po přidání `api.connection` a trvalé politiky: SETTINGS sada má 16 testů,
worker ověřuje explicitní mode, chybějící translate i nekompatibilní instanciaci;
editorové testy ověřují completion nových členů. Policy E2E prošel samostatně
(24,20 s) i v celé sadě (24,18 s). Celý běh měl 32 sad: 30 prošlo přímo,
dvě vyžadovaly aktualizaci očekávaného API schématu a offline příkladů.
API sada poté prošla; chain při opakování jednou narazil na bootstrap assertion
`active_sessions == 0`, následující samostatný běh prošel (7,62 s).
Všech 32 sad tedy má úspěšný běh; není to tvrzení o jednom čistém full-run.
Build, generovaná reference a kontrola whitespace prošly.
