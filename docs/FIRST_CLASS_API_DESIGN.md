# First Class API Design

**Status: ZÁVAZNÝ NÁVRHOVÝ KONTRAKT**  
Verze: 1.1

Datum: 2026-10-25
Rozsah: skriptovací API Spideru, Parts, editace, commit, hold a jejich prezentace.

Tento dokument určuje cílovou architekturu First Class API. Implementace,
generovaná dokumentace, editor i testy se s ním musí shodovat. Odchylka vyžaduje
výslovně schválenou změnu kontraktu; nesmí vzniknout potichu jako implementační
zkratka. Závaznost návrhu neznamená, že jsou všechny jeho části implementované.

Slova **musí**, **nesmí** a **má** označují závazné požadavky. Otevřená rozhodnutí
jsou uvedena samostatně a nesmějí být vydávána za hotový kontrakt.

## Základní filozofie

Pracujeme s **Parts**: částmi obsahu, které si nesou svůj význam, reprezentaci
a vazby na původní přenosová data. Stejná abstrakce slouží ke čtení, úpravě,
sestavení i čekání na další callback. Hold prodlužuje životnost části, nikoli
jen anonymních bajtů.

API má být nízkoprahové. Uživatel má pracovat s tím, čemu Spider skutečně rozumí,
bez ručního počítání offsetů, délek a rutinního převádění reprezentací.
Neznámý obsah je přitom plnohodnotný: absence anotace není chyba.

Skripty běží na backendu i bez otevřeného GUI. Editor zná API, poskytuje typovou
nápovědu a příklady. Referenční dokumentace se generuje z definic API, aby se
nemusela nezávisle synchronizovat s implementací.

## Zpráva a seznam Parts

`api.message` je pracovní zpráva aktuálního běhu skriptu. Její `parts` zahrnují
veškerý dostupný obsah, včetně neanotovaných mezer. Po zavedení holdu může zpráva
obsahovat podržené části z předchozích callbacků před novými částmi.

Part není automaticky jedna anotace ani jeden souvislý wire slice. Anotace se
mohou překrývat; jedna interpretovaná část může mít vazbu na více wire rozsahů.
Překryv anotací nesmí sám způsobit duplicitní emisi bajtů. Konkrétní pravidla
rozdělení překrývajících se anotací do parts jsou ještě otevřená.

Skript smí parts přeskupovat. Framework nesmí obecně zakazovat pořadí jen proto,
že je neobvyklé nebo ho protistrana nemusí přijmout. Odpovídá za sestavení známých
reprezentací a jednoznačně určených závislostí, ne za záruku úspěchu aplikace.

Přepočet hlavičky vychází z následujících **relevantních** parts. Relevantnost
musí zohledňovat konkrétní zprávu, směr a případný protokolový stream; nesmí
znamenat prostě všechny bajty za hlavičkou. Nejednoznačnou závislost commit
odmítne, místo aby ji odhadoval.

## Typy částí

Typ určuje, co part reprezentuje, ne protokol celého spojení. Například HTTP
obsah může zahrnovat MIME části. Samostatný `Protocol` přepínač není součástí
tohoto modelu.

```python
for part in api.message.parts:
    if part.is_a(PartType.Http1.Part):
        # Rodina HTTP/1 částí, například Header nebo Body.
        ...
    elif part.is_a(PartType.Mime.Part):
        ...
    elif part.type == PartType.Opaque:
        data = part.get_bytes()

return api.message.commit()
```

- `part.type == ...` porovnává přesný typ.
- `part.is_a(...)` testuje příslušnost do rodiny typů.
- `PartType.Opaque` znamená obsah bez protokolové interpretace. Má stejné základní
  operace čtení, zápisu, commit a hold jako ostatní části.
- Protokolové API musí mít oporu v anotacích nebo explicitně vytvořeném typovaném
  partu. Text připomínající HTTP uvnitř Opaque části se nesmí sám stát HTTP API.

Příklady ukazují cílové API, nikoli seznam již dostupných implementací typů.

## Lazy reprezentace a původní bajty

Parts představují významový obsah. HTTP body může být zpřístupněné jako cleartext,
i když původní wire data byla gzipovaná.

`part.get_bytes()` podle potřeby vytvoří slice, kopii nebo dekódovanou reprezentaci.
Pouhá existence, iterace nebo podržení partu nesmí vyžadovat materializaci jeho
obsahu. Pokud je vhodná reprezentace už dostupná, může se znovu použít.

Čtení nesmí označit part jako změněný. Explicitní `part.set_bytes(data)` vytváří
změnu. Nezměněný part musí zachovat původní wire bajty; nesmí se zbytečně znovu
komprimovat ani serializovat. Stejný cleartext nemusí vytvořit identický gzip.

U Opaque části je převod reprezentace na wire obsah identita. Typované části
zajišťují odpovídající serializaci nebo kódování, pokud je podporované.

Velikost reprezentace, původní wire velikost a výsledná wire velikost jsou různé
veličiny a API je nesmí skrývat pod jedním nejasným `size()`. Encoding musí být
zjistitelný přímo, ne odhadem z rozdílu velikostí. Přesné názvy těchto atributů
zůstávají otevřené.

## Dvě úrovně commitu

`part.commit()` validuje změněnou reprezentaci a připraví její wire podobu.
Například serializuje hlavičky nebo znovu zkomprimuje upravené body.
Neodesílá data protistraně. U nezměněného partu jde o levný no-op.

`api.message.commit()` provede průchod všemi částmi určenými k výstupu a jejich
commit, následovaný společným sestavením. Dopočítá známé závislosti, například
Content-Length, rámování a výstupní offsety. Explicitní volání `part.commit()`
není povinné; slouží k včasné validaci nebo získání výsledné wire velikosti.
Podržené části nejsou výstup a samotný hold jejich commit nevynucuje.

```python
for part in api.message.parts:
    if part.type == PartType.Http1.Header:
        part.http1.set_header("X-Test", "another way")
    elif part.type == PartType.Http1.Body:
        api.print(part.get_bytes().hex())
        part.set_bytes(b"\r\n\r\n\r\n")

return api.message.commit()
```

Commit nesmí během sestavování publikovat dílčí změny. Neúspěšné sestavení vyvolá
chytatelnou `CommitException`, zachová původní vstup a ponechá drafty opravitelné.
Úspěšný lokální commit nezaručuje úspěch celkového commitu. Již odeslané bajty
z minulého callbacku nelze zpětně opravit.

Výsledný obsah se předává existujícím mechanismem návratu ze skriptu.
Payloadová transakce sama o sobě neslibuje rollback externích operací,
sdíleného úložiště ani ostatních vedlejších účinků skriptu.

## Úplnost části a obsahu

```python
part.complete
part.content.complete
```

`part.complete` vyjadřuje úplnost konkrétní části, například H2 DATA rámce.
`part.content.complete` vyjadřuje úplnost příslušného celého obsahu, například
HTTP body. Kompletní DATA rámec tedy nemusí znamenat kompletní content.

Obě vlastnosti rozlišují `True`, `False` a `None`: úplné, prokazatelně neúplné,
a z dostupných informací neurčitelné. Zjištění úplnosti samo nesmí vyžadovat
zbytečné materializování decoded obsahu.

Úplný content vyžaduje známý konec i přítomnost všech potřebných částí.
Samotný END_STREAM ani úspěšný inflate to nezaručují. `content` je kontext
souvisejících částí, ne automaticky další kopie bajtů nebo samostatný stream view.

Framework nečeká magicky na budoucí callbacky. Skript, který potřebuje celý
obsah, musí příslušné části podržet. Pokud bude měnit délku body, musí zachovat
i možnost upravit související hlavičku; emitovanou hlavičku hold body nevrátí.

## Streams bez automatických pohledů

`part.stream_id` je vždy integer. U částí s protokolovým stream ID obsahuje
skutečné ID; jinak má hodnotu **1**, včetně Opaque částí. Skutečná nula zůstává
nulou, například u connection-level H2 rámců.

```python
for part in api.message.parts:
    if part.stream_id == 1:
        # Záměrně zahrnuje skutečný stream 1 i části s výchozí hodnotou.
        ...
```

Výběr a seskupování provádí skript. API zatím nevytváří automatické per-stream
views ani pořadí podle streamů. Interní vazby nesmějí vycházet pouze z veřejného
`stream_id`: výchozí 1 nedokazuje příslušnost Opaque části k H2 streamu 1.

## Hold uchovává celé Parts

Free-form `hold(N)` nad bajty není cílový model. Zadržujeme celé parts se zachováním
jejich významu, nikoli bajty určené k novému rozpoznávání.

```python
api.message.parts.hold_from(part)
```

Tato operace zadrží označenou část i všechny následující části v aktuálním pořadí.
Předcházející prefix může být sestaven a odeslán. Skript může před operací seznam
přeskupit; neexistuje obecný zákaz, že původně pozdější part nesmí předběhnout
podržený part.

Hold buffer zachovává typ, stream ID, úplnost, anotace, interní vazby, původní
wire obsah, lazy reprezentaci, rozpracované změny a případný výsledek lokálního
commitu. Hold sám nevynucuje decode ani commit. Podržené části se z aktuálního
výstupu zkonzumují a protistraně nesmějí odejít.

Další běh dostane podržené parts před novými se zachovaným pořadím. Backend musí
uchovat jejich významový stav mezi zanikajícími Python workery; nesmí se spoléhat
na přežití Python objektů. Životnost transportně podrženého obsahu nelze zaměnit
za životnost uživatelského `api.state`.

Podržení musí být izolované minimálně podle deploymentu, spojení a směru;
endpoint instancing nesmí smíchat data různých spojení. Přesné transakční chování
mezi více skripty a při změně deploymentu je otevřený implementační kontrakt.

## Vlastní typované Parts

Skript může do seznamu vložit nově vytvořený part, například cílově:

```python
ping = api.http2.Ping(opaque_data=b"12345678")
api.message.parts.append(ping)
```

Nový part nemá původní wire rozsahy, ale sdílí stejný commit kontrakt. Typovaná
serializace kontroluje požadavky konkrétního typu; příklad PING konstruktoru
není příslib již implementované podpory. Interakce vložených řídicích rámců
s protistranou, například zpracování ACK, musí mít výslovně určené chování.

## Stavové dekódování a anotace

Živý stavový engine zpracovává každý nový příchozí bajt právě jednou. Složený
vstup skriptu obsahující podržené parts se nesmí znovu přehrát do živého HPACK
nebo dekompresního stavu.

```text
nový vstup → stavový enrichment → nové parts
                                    + podržené parts
                                    ↓
                               pracovní zpráva
                                    ↓
                         editace / hold / commit
```

Přesuny a sestavení přepočítávají souřadnice a vazby anotací. Framework nemusí
opravovat jejich původní věcnou správnost ani překryvy. Musí ale zachovat původ
odvozených reprezentací; enrichment přes více callbacků není obyčejný slice.

Stav dekodéru příchozího streamu a stav protistrany po změnách výstupu nejsou
totéž. Zvláště zápisy do HPACK nelze prohlásit za bezpečné pouze proto, že
umíme serializovat jednu hlavičku.

## Viditelnost změn v GUI

Publikace do GUI musí jednoznačně sdělit alespoň to, že se obsah změnil nebo
byl podržen. Původní payload a jeho anotace nesmějí být vydávány za skutečně
odeslaný změněný výstup.

Metadata zpracování mají odlišit příchozí, změněný, podržený, uvolněný a odeslaný
obsah a identifikovat původní callbacky a zasahující skript. Přesné názvy polí
a rozsah uchovávaného výstupního obsahu nejsou zatím stanovené. Pouhý příznak
změny neopravňuje GUI zobrazovat rekonstruovaný výstup jako skutečně zachycený.

## Otevřená rozhodnutí a vědomě odložená ochrana holdu

- Atomická návaznost hold bufferů a výstupu v řetězci více skriptů.
- Chyba, timeout nebo nedostupný worker po předchozím úspěšném holdu. Běžné
  „pusť jen aktuální originál“ není dostatečné: ztratilo by starší zadržené části.
- Ukončení spojení, disable, redeploy, změna filtru a restart backendu.
- Limity paměti, délky čekání a politika při jejich překročení.
- Serializace a verzování uchovávaných parts, včetně neúplných reprezentací.
- Způsob doplnění neúplného partu nebo content kontextu dalšími callbacky bez
  dvojího průchodu živým dekodérem.
- Přesná pravidla překryvů anotací, rozdělení parts a vazeb mezi nimi.
- Chování `return None`, chyb a ad-hoc preview při práci s hold bufferem.

Pro první živou implementaci bylo výslovně schváleno ponechat **fail-open** a
výpadkovou ochranu odložit do `docs/TODO.md`. Výpadek po need-more může porušit
úplnost/pořadí přenosu; současný hold tento problém neřeší. Normální úspěšná cesta
musí nadále zabránit předčasné nebo dvojité emisi. Nejde o režim TRANSLATE.

Živý hold je nyní dostupný v posledním zapnutém deploymentu s instanciací `flow`.
Checkpointy jsou oddělené podle deploymentu/generace, spojení a L/R směru;
nejsou uživatelským `api.state` ani stavem procesu Pythonu. Jsou to verzovaná,
typovaná JSON data bez pickle. Limit je 1 MiB serializovaného checkpointu,
celkově 4 MiB na deployment včetně instance state. Převzetí nastává jen úspěšným
vrácením výsledku `message.commit()`: prázdný prefix vrací `need-more`, neprázdný
prefix `replace`. Další callback obnoví původní Parts a jejich drafty.

`return None` po obnovení holdu je chyba: skript musí explicitně vrátit výsledek
nebo znovu podržet části. Preview a message/endpoint instanciace hold odmítnou.
Při chybě vykonaného skriptu se dřívější hold daného směru opustí s metadaty
`hold.state=abandoned`; aktuální fragment se podle dnešní politiky pustí beze změny.
Checkpoint se odstraní také s instancí při stop/expiry/redeploy; není persistentní
přes restart backendu. Tato omezení musí být viditelná v dokumentaci.

## Vztah k současné implementaci

Existuje write API přes `api.message.snapshot()` a monolitický `draft.http1`,
s privátním commitem a přepočtem Content-Length pro omezenou množinu kompletních
HTTP/1 zpráv. Živý H1 Parts/hold nyní podporuje anotovanou úplnou hlavičku s jedním
Content-Length a tělem doplňovaným dalšími callbacky, bez komprese. H1 Header
vystavuje `part.http1`, Body `get_bytes/set_bytes`; commit přepočítá Content-Length.

První živá H2 implementace používá `api.message.parts` v režimu REWRITE:
anotované framy, celé lokální HEADERS/PUSH_PROMISE + CONTINUATION bloky a Opaque
mezery. Neúplné části lze zachovat, nikoli přestavět. HPACK pole, explicitní
indexy, table-size updates, DATA a vlastní framy jsou zapisovatelné. Celý lokálně
známý content umožňuje přepočet Content-Length. `commit(False)` tento přepočet
explicitně vypíná pro assemblerové/research úpravy.

`part.complete` značí úplný frame/header blok, `part.content.complete` úplný
lokálně známý content (`True`), rozpracovaný (`False`), nebo neznámý (`None`).
U DATA bez lokální počáteční hlavičky není END_STREAM samo důkazem celého contentu.
Komprese contentu, obecné překryvy anotací a TRANSLATE zatím nejsou implementované.
H2 hold uchovává i neúplné framy s dostupnou devítibajtovou hlavičkou a neúplné
HEADERS/CONTINUATION bloky; jejich obsah se doplňuje bez opakovaného průchodu
živým HPACK dekodérem. Strukturální H2 části se sestavují při vytvoření callbackového
API. DATA a Opaque drží view původních bajtů; `get_bytes()` je materializuje až
při čtení. Nezměněný commit je nekopíruje do jednotlivých reprezentací znovu.

Současné rozpoznání HTTP/1 snapshotu přímo z bajtů musí být při přechodu na Parts
nahrazeno interpretací opřenou o anotace. Monolitický snapshot není vzor pro
další růst veřejného API; jeho validační a serializační logika může sloužit
jako stavební dílek jednotlivých parts a jejich společného commitu.

## REWRITE a TRANSLATE

Výchozí **REWRITE** sestaví výhradně explicitně upravený aktuální obsah. Nikdy
neaktivuje skryté přepisy dalších callbacků. Engine zajistí serializaci délek
framů, rozdělení DATA/header bloků a podporované lokální závislosti. Nezajišťuje
smysluplnost hodnot, kompenzaci flow-control oken ani budoucí shodu HPACK tabulek
obou protějšků. Explicitní
index může odkazovat na neexistující položku; validní HPACK instrukce neznamená,
že ji protějšek ve svém stavu přijme. To je vědomá odpovědnost autora skriptu.
Nezměněné HPACK instrukce i celé nezměněné framy zachovají originální bajty.

Budoucí **TRANSLATE** musí uživatel explicitně aktivovat. Vyžaduje dostupnost
celého dalšího contentu spojení a alespoň flow instanciaci. Každá výstupní
modifikace musí projít explicitním voláním skriptu; žádné magické opravy mimo
uživatelský běh. Chyba nebo chybějící nutný překlad znamenají ukončení spojení,
nikoli pokračování s nekonzistentním stavem. REWRITE může mít odlišnou politiku
chyb (dnes živá exekuce fail-open). Protokolové řízení/strict a potvrzení jeho
aktivace jsou odložené; tento kontrakt netvrdí, že už existují.

## Ověřovací kritéria

Testy implementace musí pokrývat zachování původních wire bajtů po pouhém čtení,
lazy materializaci, Opaque mezery, typovou hierarchii a výchozí stream ID 1.
Dále musí odlišovat úplnost rámce od contentu, ověřovat atomický commit a
opakovaný pokus po CommitException a prokázat zachování významu parts přes hold.

Transportní testy musí ověřit, že podržený obsah neodejde předčasně, po uvolnění
neodejde dvakrát, nesmíchá se mezi spojeními a znovu nevstoupí do živého dekodéru.
GUI testy musí odlišovat původní vstup od změněného nebo podrženého výstupu.

### Ověření první H2 REWRITE implementace — 2026-10-25

- `ctest --test-dir build --output-on-failure -j 2`: **17/17 prošlo**.
- `tests/inspection_h2_test.py`: **17 testů**, včetně 200 deterministických
  náhodných no-op/partial vstupů a 100 sad binárních HPACK literálů. Výstup
  ověřuje nezávislý dekodér libnghttp2, nikoli vlastní encoder/parser.
- Pokryté jsou Huffman/indexované vstupy, explicitní table/index editace,
  padding/priority, PUSH_PROMISE, CONTINUATION, hranice velikostí, END_STREAM,
  Content-Length, přidání/odebrání DATA, Opaque mezery, lazy materializace,
  atomické selhání/retry a explicitní publikace výsledku workerem.
- `spider_chain_test`: skutečný lokální webhook s backendovým HPACK enrichmentem,
  sandboxovaným rewritem a nezávislým dekódováním náhrady; vypnutí skriptu znovu
  ponechá callback beze změny. Žádný překlad nepokračuje skrytě.
- Jazykové testy ověřují typy parts, hlaviček, položek HPACK i konstruktorů.
- `tests/browser_smoke.py --repeat 1`: **prošlo**, izolovaná regrese editoru
  a oddělení library/deploy/draft. Netestuje živý H2 provoz v browseru; ten
  pokrývá výše uvedená backendová integrace.

### Živý hold — ověření 2026-10-25

- Celá sada rozšířena na **19 testovacích sad**, všechny prošly také v UBSan.
- `inspection_hold_test.py`: **11 testů**; všechny řezy H1 body a H2 DATA,
  opakované checkpointy přes skutečně nové workery, zachování rozpracovaných
  hlaviček a délkových závislostí po odstranění DATA, prefix emit, limity, chybné
  anotace a odmítnutí nepodporovaných režimů.
- `inspection_hold_live_tests`: skutečný backendový handler + pool; prokládaná
  spojení a oba směry, souběžné callbacky, postup po jednom bajtu, jeden výsledný
  replace, stop/redeploy bez přenosu starého holdu do nové generace a dnešní
  fail-open při chybě. H2 HEADERS/CONTINUATION používá skutečné HPACK enrichmenty.
- `spider_chain_test`: HTTP callbacky vrátí dvakrát čisté `need-more`, poté jediný
  `replace` s přepsaným body a novým Content-Length. Nevyžaduje běžící lab1.
- Výsledky testů negarantují zotavení při výpadku backendu/proxy; to zůstává
  výslovně odloženou položkou TODO, nikoli implicitně vyřešenou vlastností.

### Rozšířené deterministické korpusy — 2026-10-25

- Ověření: standardní build a **21/21 CTest sad prošlo**, celkem 26,17 s.
  Tento běh není novým UBSan během; výsledek UBSan výše patří předchozí sadě.
- `inspection_h1_corpus_tests`: request i response, prázdné body, všechny hodnoty
  bajtu, UTF-8, JSON, nulové bajty, HTTP-like obsah uvnitř body, náhodná data
  a 64 KiB+1 body. Matice 54 přepisů s různými fragmentacemi a délkami náhrady;
  dalších 69 řezů ověřuje přesné zachování body i navazujícího Opaque obsahu.
  Samostatně 24 prokládaných checkpointů a oprava draftu po neúspěšném commitu.
- `inspection_h2_corpus_tests`: 40 kombinací délky DATA a stream ID včetně hranic
  16383/16384/16385, rozdělení rámců a END_STREAM; 27 kombinací HPACK délky
  a indexing režimu, HEADERS/CONTINUATION ověřené přes libnghttp2; 16 prokládaných
  streamů s nezávislým Content-Length; 128 řezů DATA s opakovanými checkpointy;
  100 náhodných neznámých rámců zachovaných byte-for-byte.
- Generátory používají pevné seedy, chyby jsou reprodukovatelné. Obě sady jsou
  součástí CTest s timeoutem 30 sekund. Jde o transakční/serializační testy,
  nikoli náhradu existujících živých webhook a worker-pool integrací ani důkaz
  stoprocentního pokrytí všech vstupů.
