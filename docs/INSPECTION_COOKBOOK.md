# Inspection cookbook

## Setup před živým přepisem

Živý skript nyní dostane také `connection-start`: `api.phase == 'setup'`,
`api.message is None`, metadata jsou v `api.info`. V této fázi musí explicitně
zavolat `api.connection.request_rewrite()` a vrátit `None`, pokud bude později
měnit délku nebo používat hold/Translate. Bez opt-in smí vrátit `None` nebo
replacement **přesně stejné délky v bajtech jako vstup daného callbacku**,
v Easy **i** Expert. Pozdní opt-in vyvolá `CommitException`; pouhé zapnutí Expert
rezervaci neudělí.

Stejně dlouhý raw replacement tiše projde, i když mění hlavičky nebo stavová pole.
Proxy zůstane u jediného vstupního kontextu: nic nepřepočítává pro druhý pohled,
nezapíná Translate ani dodatečný fork. Správnost protokolu, obsah, digesty a
případné rozbití dalších zpráv jsou odpovědnost skriptu. Kontroly typed `commit()`
v Easy/Expert tím neměníme; raw výstup žádnou takovou kontrolu neslibuje.
Počítá se výsledná délka celého replacementu, ne počet znaků, base64 délka ani
jen délka upraveného body. Změna délky bez rezervace skončí `CommitException` ve
workeru; přímou nepovolenou webhookovou odpověď proxy odmítne zavřením spojení.

<!-- example: same-size-without-reservation fixture=h1-unreserved expect=replace -->
```python
if api.phase == 'setup':
    return  # Žádná rezervace druhého kontextu.
# Jednoduchý raw přepis; délka se nezmění, parserovou konzistenci nehlídáme.
return api.bytes.replace(b'abc', b'xyz')
```

Před následující payloadové příklady proto při živém deploymentu přidej tento
guard. Náhledy nad uloženými vzorky mají `api.phase == 'content'` a rezervaci
nepotřebují. Setup samo nezapíná Translate: obsah dál vyžaduje explicitní
`return api.message.translate()` v každém jeho callbacku.

<!-- example: reserve-rewrite fixture=setup expect=setup -->
```python
if api.phase == 'setup':
    api.connection.request_rewrite()
    return
# Zde pokračuje vlastní payloadový příklad.
return None
```

Rezervace platí pro spojení; změna deploymentu uprostřed již běžící nerezervované
session ji nemůže dodatečně udělit. Filtr i scope se vyhodnocují už při setupu,
takže mohou používat jen metadata dostupná v tuto chvíli, nikoli budoucí L7
anotace. Chyba setupu nepublikuje rezervaci. Ve flow instanci se úspěšně
uložené `api.state` přenese ze setupu do prvního content callbacku.

## Easy a Expert

Výchozí je `Safety.Easy`. Volba `commit(safety=Safety.Expert)` platí jen pro toto
volání; samostatný `part.commit()` ani hold ji nepřenese do dalšího commitu.
Stejný parametr podporuje snapshot, message i translate. Je nezávislý na
`Mode.Rewrite` / `Mode.Translate`, instanciaci i scope deploymentu.

| Oblast | Easy | Expert |
|---|---|---|
| H1 podporovaný Content-Digest | Přepočítá | Přepočítá |
| H1 změna těla s nepodporovanými encoding/digest/range/signature metadaty | Odmítne | Ponechá metadata na odpovědnosti skriptu |
| H1 Host a bodyless status | Kontroluje sémantiku při změně | Povolí nesoulad |
| Známé Content-Length | Přepočítá | Přepočítá stejně; Expert není implicitní vypnutí oprav |
| H2 control nad nastaveným max_frame_size | Odmítne při commitu; limit lze nastavit předem | Povolí v mezích fyzické reprezentace a kvóty |
| H2 fragmentace pod 16384 | Odmítne | Povolí, má-li rámec kladnou kapacitu pro data |
| Neúplný editovaný part, konfliktní raw/typed zápis, kvóta, duplicitní objekt | Odmítne | Odmítne |
| Translate HPACK/strict/flow-control podmínky | Zachová | Zachová; nejde o implicitní přechod do rewrite |

`message.commit(False, safety=Safety.Expert)` vypíná pouze známý přepočet H2
Content-Length. H1 typed assembly přepočítává délku vždy. Komprimované H1 Parts,
chunked, trailers, upgrade a nejednoznačné vstupní framing zůstávají nepodporované
v obou režimech; Expert je neimplementuje a neprovádí automatickou kompresi.

Easy znamená existující sémantické ochrany, **ne úplný protokolový validátor**.
Například H2 rewrite ani v Easy neudržuje stav vzdálené HPACK tabulky; nezměněné
bajty včetně neznámých rámců zachovává. Typované hodnoty dál vyžadují jednoznačné
kódování (například header name bez CR/LF nebo kladný HPACK index); explicitní
raw výstup není bezpečnostní filtr. Stejně tak storage operace, čtení a settery
nejsou závislé na safety commitu. Přesná pravidla **každého** pole a metody jsou
v [generované referenci](API_EXAMPLES_REFERENCE.md), browser API Reference a
editorové nápovědě. Automatický fallback z Easy do Expert neexistuje.

Stejná změna s neplatným digestem: Easy ji odmítne, Expert sestaví záměrně
nekonzistentní zprávu. Ostatní příklady bez parametru `safety` používají Easy.

<!-- example: easy-digest fixture=h1 expect=CommitException -->
```python
draft = api.message.snapshot()
draft.http1.set_header("Digest", "old-digest")
draft.http1.body = b"changed"
return draft.commit(safety=Safety.Easy)
```

<!-- example: expert-digest fixture=h1 expect=replace -->
```python
draft = api.message.snapshot()
draft.http1.set_header("Digest", "old-digest")
draft.http1.body = b"changed"
return draft.commit(safety=Safety.Expert)
```

Živé spojení má také `api.connection`: explicitní režim přes `set_mode(Mode.Translate)`
a trvalou H2 politiku přes `http2.enforce_header_table_limit(0)`. Praktický kontrakt
a příklad jsou v [H2 translate](H2_TRANSLATE_LIVE.md); vyžadují živou flow instanci,
nikoli offline fixture. Settery nenahrazují `return api.message.translate()`.

Krátké scénáře pro vlastní lab a autorizované testování. Každý blok vlož jako
samostatný skript. Nejde o skripty, které se mají spustit všechny za sebou.
Test `inspection_cookbook_tests` spouští všechny zdejší Python bloky ve skutečném
workeru nad označenými fixture payloady, včetně očekávaných chyb.

## H1 změna obsahu s Content-Digest

Úplné nekomprimované H1 tělo lze změnit přes snapshot i Body part. Commit
přepočítá Content-Length a existující nebo nově nastavený Content-Digest.
Podporujeme `sha-256` a `sha-512`, včetně obou současně a více řádků hlavičky
(výstup se sjednotí do jednoho řádku). Jde o byte-sequence dictionary podle
[RFC 9530 §2](https://www.rfc-editor.org/rfc/rfc9530.html#section-2).

<!-- example: content-digest-repair fixture=h1 expect=replace -->
```python
draft = api.message.snapshot()
draft.http1.body = b"changed"
# Prázdná byte sequence je vstup pro sestavení, commit doplní skutečný hash.
draft.http1.set_header("Content-Digest", "sha-256=::, sha-512=::")
return draft.commit()
```

Easy i Expert opravují podporované digests. Expert není vypínač přepočtu.
Neznámé algoritmy, parametry členů, opakované algoritmy a neplatná syntaxe
jsou zatím nepodporované: Easy vyvolá CommitException, Expert zachová celý
slovník beze změny (žádná částečná oprava). Úplný no-op zachová původní bajty;
nezměněné digests se neověřují. Samotné čtení snapshotu tedy není validace integrity.
Odstranění Content-Digest je explicitní odstranění tohoto tvrzení o integritě.

Repr-Digest, ETag, podpisy, Content-Range, chunked/trailers a komprese zůstávají
mimo tento krok. Easy dál odmítne změnu těla, pokud má takovou neřešitelnou
závislost. Hlavičku s digestem nelze odeslat před jeho výpočtem: u neúplných
Parts podrž celou H1 zprávu od Header partu a commitni až po dosbírání těla.
Draft se přepočtem nemění a neúspěšný commit nic nepublikuje.

## Co znamená 100% pokrytí

[Úplný inventář](API_EXAMPLES_REFERENCE.md) obsahuje příklad **každého členu
aktuálního typovaného API schematu**. Generátor a test odmítnou zastaralý dokument;
`inspection_api_tests` navíc každý schema příklad vykonává nad prázdnými,
naplněnými i neúplnými callbacky. Níže jsou praktické scénáře a chyby.
Starší ploché helpery jsou souhrnně ukázané v prvním příkladu.

Ověření 2026-10-25: schema v0.5 má 20 typů a 82 členů; cookbook obsahuje
21 samostatných spustitelných bloků. Celá sada **22/22 CTest testů prošla**
(29,17 s). Nové dokumentační testy používají skutečný sandboxovaný worker;
nejde o nový UBSan ani produkční load test.

To neznamená 100% branch coverage, všechny kombinace protokolu ani záruku
bezchybnosti. `PartType` podporuje `Opaque`, `Http1.Part/Header/Body`
a `Http2.Part/Header/Data/Frame`; `part.is_a(...)` testuje rodinu typu.
`HeldCommit` je neprůhledný výsledek: pouze ho vrať, nevyráběj ani neserializuj ho.

## Základní pravidla

- Read-only views popisují vstup; `message.parts` jsou editovatelné drafty.
- `get_bytes()` materializuje bajty až při čtení. Komprese zde zatím není write API.
- `part.commit()` vrací lokální bajty; teprve `return api.message.commit()` publikuje
  sestavenou zprávu. Samotné volání commitu neposílá nic.
- `complete` znamená úplný part; `content.complete` celý známý content
  (`True`, `False`, nebo `None`, pokud ho nelze určit).
- Hold vyžaduje živý flow deployment, poslední v povoleném řetězci, směr L/R.
  Run on selected ani message/endpoint instanciace transportní hold nepodporují.
- REWRITE nepřekládá pozdější zprávy. Změnou HPACK tabulky můžeš rozladit spojení.
- Chyba skriptu má nyní fail-open chování. Po chybě s drženými daty nelze zaručit
  neporušený tok; strict/drop a ochrana při výpadku jsou zatím TODO.
- Limity: náhrada 1 MiB, checkpoint 1 MiB, kombinovaný prefix/checkpoint 1,5 MiB,
  state 64 KiB, state+hold 4 MiB na deployment. U velkých vstupů počítej s chybou.

## 1. Diagnostika bez změny provozu

Metadata mohou obsahovat tajné údaje; zde vypisujeme jen omezené náhledy.
Ploché helpery jsou kompatibilní starší rozhraní. L7 ranges jsou offsety
do původních `api.bytes`, ne do sestaveného draftu.

<!-- example: observe fixture=h1 expect=unchanged -->
```python
api.print(api.session_id, api.session_label, api.side)
api.print("decoded views", api.http1.available, api.http2.available)
api.print(len(api.bytes), api.text[:40])
api.print(api.event.get("id"), api.info.get("payload_layer"))
api.print(api.annotations, len(api.enrichments))
api.print(api.l7_state, api.l7_ranges, api.l7_encodings)
api.print(api.l7_bytes[:16].hex())
api.print(api.hexdump(limit=32, width=8))
return None
```

## 2. H1: změnit cestu a přidat identifikátor testu

Snapshot je nezávislý draft kompletní H1 zprávy. `set_header` nahrazuje duplicity;
pro zachování opakovaných hlaviček přidej přímo `Header(name, value)` do seznamu.

<!-- example: h1-route fixture=h1 expect=replace -->
```python
draft = api.message.snapshot()
if not draft.http1.available:
    return None
draft.http1.target = "/lab/echo"
draft.http1.remove_header("X-Old")
draft.http1.set_header("X-Test-ID", "spider-lab")
draft.http1.headers.append(Header("X-Tag", "first"))
draft.http1.headers.append(Header("X-Tag", "second"))
return draft.commit()
```

## 3. H1 Parts: přepsat body a opravit délku

Bez komprese, s jedním Content-Length a anotovanou kompletní hlavičkou.
HTTP-looking text v body není nová hlavička. Délku počítáme v bajtech.

<!-- example: h1-body fixture=h1 expect=replace -->
```python
for part in api.message.parts:
    if part.is_a(PartType.Http1.Part):
        api.print(part.type, part.content.complete)
    if part.type == PartType.Http1.Body:
        part.set_bytes(b'{"lab":true}')
return api.message.commit()
```

## 4. H1: počkat na zbytek body

První callback obsahuje hlavičku a jen `a` z body `abc`. Druhý dodá `bc`.
První výsledek je `need-more`, druhý jediný `replace` s opravenou délkou.
Zadržujeme od hlavičky, protože její Content-Length ještě musíme upravit.

<!-- example: h1-hold fixture=h1-partial expect=hold-resume -->
```python
for part in api.message.parts:
    if part.type == PartType.Http1.Header and not part.content.complete:
        api.message.parts.hold_from(part)
        return api.message.commit()
    if part.type == PartType.Http1.Body:
        part.set_bytes(part.get_bytes() + b"-checked")
return api.message.commit()
```

## 5. H2: označit testovací request

Pracujeme pouze se streamem 3. Hodnoty rewrite hlaviček jsou `bytes`, zatímco
read-only dekódované views používají text. Lokální commit můžeš použít k náhledu.

<!-- example: h2-header fixture=h2 expect=replace -->
```python
for part in api.message.parts:
    if part.stream_id == 3 and part.type == PartType.Http2.Header:
        part.headers.set_header(b"x-test-id", b"spider-lab")
        api.print("encoded bytes", len(part.commit()))
return api.message.commit()
```

## 6. H2: větší DATA a automatické rozdělení rámců

V testovací odpovědi/requestu změníme body na 20 KiB. Engine rozdělí DATA,
ponechá END_STREAM poslednímu rámci a opraví známý Content-Length.

<!-- example: h2-body fixture=h2 expect=replace -->
```python
for part in api.message.parts:
    if part.type == PartType.Http2.Data:
        part.max_frame_size = 16384
        part.set_bytes(b"A" * 20000)
return api.message.commit()
```

## 7. H2: explicitní HPACK a vlastní rámce

Pouze izolovaný lab. Index 2 je statický `:method: GET`; index 62 už může záviset
na dynamické tabulce. Table-size update musí být před hlavičkami. Incremental
indexing mění stav peeru — pozdější zprávy za tebe rewrite neopraví.

<!-- example: h2-construct fixture=h2 expect=replace -->
```python
for part in api.message.parts:
    if part.type == PartType.Http2.Header:
        part.headers.entries = [
            api.http2.TableSize(4096),
            api.http2.HeaderIndex(2),
            api.http2.Header(b"x-lab", b"value", "incremental"),
            api.http2.Header(b"authorization", b"lab-only", "never"),
        ]
api.message.parts.append(api.http2.Ping(b"lab-ping"))
api.message.parts.append(api.http2.Frame(0, 1, 5, b"lab"))
return api.message.commit(False)
```

`commit(False)` vypíná automatickou opravu Content-Length, nikoli validaci
serializace. Zde je výsledná návaznost streamů vědomě odpovědností autora testu.

## 8. Opaque: známý vlastní binární formát

Bez anotací engine neháda HTTP. U vlastního protokolu můžeš explicitně měnit
Opaque obsah; tím na sebe bereš odpovědnost za jeho framing.

<!-- example: opaque fixture=opaque expect=replace -->
```python
for part in api.message.parts:
    if part.type == PartType.Opaque:
        part.set_bytes(part.get_bytes() + b"\x00")
return api.message.commit()
```

## 9. Instance a sdílené počítadlo

`state` žije podle instanciace (message/flow/endpoint), nikoli jako Python global.
Sdílené storage operace jsou jednotlivě atomické, ale jejich sekvence není
transakce. Zápis do storage se nevrací zpět při pozdější chybě skriptu.

<!-- example: counters fixture=h1 expect=unchanged -->
```python
api.print(api.instance.mode, api.instance.key,
          api.instance.deployment_id, api.instance.version)
api.state["callbacks"] = api.state.get("callbacks", 0) + 1
shared = api.storage.namespace("lab-cookbook")
shared.set("last", {"side": api.metadata.side})
api.print(shared.get("last", {}))
api.print(shared.increment("callbacks"))
shared.delete("last")
return None
```

## 10. Commit bez return nic nepublikuje

<!-- example: discard-draft fixture=h1 expect=unchanged -->
```python
draft = api.message.snapshot()
draft.http1.body = b"not published"
draft.commit()
return None
```

## 11. Chyba: CRLF v H1 hlavičce

Engine odmítne vložení dalšího řádku přes hodnotu. Nezachycený CommitException
znamená neúspěšný skript a žádnou replacement hodnotu, nikoli částečný přepis.

<!-- example: bad-header fixture=h1 expect=CommitException -->
```python
draft = api.message.snapshot()
draft.http1.set_header("X-Test", "value\r\nInjected: yes")
return draft.commit()
```

## 12. Zachycená chyba a oprava draftu

<!-- example: retry fixture=h1 expect=replace -->
```python
draft = api.message.snapshot()
draft.http1.target = "/bad target"
try:
    return draft.commit()
except CommitException:
    draft.http1.target = "/safe"
    return draft.commit()
```

## 13. Chyba: editace gzip body bez encoderu

Snapshot dovoluje původní zprávu beze změny, ale změna zakódovaného body není
podporovaná. Totéž platí pro nepřepočitatelná integrity/range metadata.

<!-- example: encoded-body fixture=gzip expect=CommitException -->
```python
draft = api.message.snapshot()
draft.http1.body = b"plain text is not gzip"
return draft.commit()
```

## 14. Chyba: neúplná H1 zpráva bez holdu

<!-- example: incomplete fixture=h1-partial expect=CommitException -->
```python
return api.message.commit()
```

## 15. Chyba: neplatný PING / HPACK pořadí

PING musí mít přesně osm bajtů; table-size update nesmí následovat pole hlavičky.

<!-- example: ping-size fixture=h2 expect=CommitException -->
```python
api.message.parts.append(api.http2.Ping(b"short"))
return api.message.commit()
```

<!-- example: table-order fixture=h2 expect=CommitException -->
```python
for part in api.message.parts:
    if part.headers is not None:
        part.headers.entries.append(api.http2.TableSize(0))
return api.message.commit()
```

## 16. Chyba: stejný part ve výstupu dvakrát

Kopii vytvoř explicitně konstruktorem; nepřidávej stejný objekt podruhé.

<!-- example: duplicate fixture=h2 expect=CommitException -->
```python
api.message.parts.append(api.message.parts[0])
return api.message.commit()
```

## 17. Chyba: neplatné sdílené počítadlo

Storage obsahuje JSON hodnoty; increment není konverze textu na číslo.

<!-- example: bad-counter fixture=h1 expect=TypeError -->
```python
shared = api.storage.namespace("lab-cookbook")
shared.set("bad-counter", "three")
shared.increment("bad-counter")
```

## 18. Chyba: hold v náhledu, nebo bez vrácení výsledku

První ukázka běží jako Run on selected (bez flow deploymentu): commit lokálně
vyrobí výsledek, ale worker odmítne transportní hold. Druhá nevrací commit vůbec.

<!-- example: hold-preview fixture=h1-partial expect=CommitException -->
```python
api.message.parts.hold_from(api.message.parts[0])
return api.message.commit()
```

<!-- example: hold-no-return fixture=h1-partial expect=CommitException -->
```python
api.message.parts.hold_from(api.message.parts[0])
return None
```

## 19. Chyba: příliš velká náhrada

Do 1 MiB se musí vejít celá náhrada včetně hlaviček, ne jen body.

<!-- example: too-large fixture=h1 expect=CommitException -->
```python
draft = api.message.snapshot()
draft.http1.body = b"A" * (1024 * 1024)
return draft.commit()
```

## Další důležité hranice

- H1 Parts zatím nejsou parser chunked/compressed/pipelined zpráv. Bez vhodných
  anotací dostaneš Opaque, nikoli automaticky rozpoznané HTTP.
- Neúplný H2 rámec může být zachovaný beze změny, ale nelze ho libovolně přepsat;
  hold dnes potřebuje kompletní devítibajtovou frame header.
- Unresolved HPACK index nemusí mít `name`/`value`; `set_header` pak může selhat.
  Explicitní index může být serializovatelný a přesto nesmyslný pro peer.
- Read-only dataclasses ani memoryviews nejsou editovatelné. Použij draft/Parts.
- Smazaný či zdvojený hold boundary, příliš velký checkpoint, `return None`
  po obnovení holdu nebo hold bez `return message.commit()` jsou chyby.
- Storage může hlásit contention/infrastrukturní chybu `StorageBusy`;
  sandbox blokuje síť a nepovolené soubory. To nejsou validační chyby payloadu.
